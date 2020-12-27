from collections import defaultdict
import logging
import certifi
from datetime import datetime


from jira import JIRA, JIRAError, Issue as _JiraIssue

from easypy.concurrency import synchronized
from easypy.resilience import resilience
from easypy.timing import Timer
from easypy.units import MINUTE
from easypy.collections import ilistify, iterable, chunkify
from easypy.caching import locking_cache, cached_property
from easypy.properties import safe_property
from easypy.bunch import bunchify
from easypy.aliasing import aliases
from easypy.tokens import NO_DEFAULT
from easypy.exceptions import PException
from easypy.collections import SimpleObjectCollection

from .common import trim, MAX_TEXT_LENGTH


_logger = logging.getLogger(__name__)


# When querying Jira with MultiObject limit workers
# to avoid errors
JIRA_MAX_WORKERS = 3


DEFAULT_TIMEOUT = 300


class JiraException(PException):
    pass


class LoginException(JiraException):
    pass


class UndefinedFieldException(JiraException):
    pass


MISSING_SCHEMAS = {
    'Status': dict(name="Status", field_id="status", schema=dict(type='status')),
    'Created': dict(name="Created", field_id="created", schema=dict(type='date')),
    'Updated': dict(name="Updated", field_id="updated", schema=dict(type='date')),
    'Resolution': dict(name="Resolution", field_id="resolution", schema=dict(type='obj')),
}


class Field(object):

    def __init__(self, display_name, default=NO_DEFAULT):
        self.display_name = display_name
        self.default = default

    def __eq__(self, other):
        return self.__dict__ == other.__dict__


FIELD_ALIASES = dict(
    assignee=Field("Assignee"),
    components=Field("Components"),
    created=Field("Created"),
    fix_versions=Field("Fix versions"),
    affects_versions=Field("Affects versions"),
    issue_type=Field("Issue Type"),
    labels=Field("Labels"),
    reporter=Field("Reporter"),
    resolution=Field("Resolution"),
    status=Field("Status"),
    summary=Field("Summary"),
    description=Field("Description"),
    updated=Field("Updated"),
    priority=Field("Priority"),
    environment=Field("Environment"),
)


def to_jira_time(dt: datetime):
    assert isinstance(dt, datetime) and dt.tzinfo
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000%z")


@aliases("_CLIENT", static=False)
class JiraClient():

    REGISTRY = defaultdict(dict)
    _CLIENT_EXPIRATION = MINUTE * 7
    __CLIENT = None

    class JiraProject(object):
        # gets populated by JiraClient._fetch_meta
        @classmethod
        def is_issue_key(cls, string: str) -> bool:
            return string.startswith(f"{cls.key}-")

    def __init__(self, url, login, GenericIssue=None):
        self.url = url
        self.login = login
        self._meta = bunchify(MISSING_SCHEMAS)
        if not GenericIssue:
            from .issue import GenericIssue
        self.GenericIssue = type("GenericIssue", (GenericIssue, ), dict(_CLIENT=self))
        self._fetch_meta()

    @cached_property
    def all_users(self):
        return SimpleObjectCollection(
            (u for u in self.users() if hasattr(u, "emailAddress")),
            ID_ATTRIBUTE="emailAddress", name="users")

    @safe_property
    def active_users(self):
        return self.all_users.filtered(active=True)

    @classmethod
    def register(cls, issue_cls):
        if not issue_cls.PROJECT:
            return
        if issue_cls.__name__.startswith("_"):
            return
        cls.REGISTRY[issue_cls.PROJECT][issue_cls.NAME or issue_cls.__name__] = issue_cls
        for name, dn in issue_cls.FIELDS.items():
            dn = dn if isinstance(dn, Field) else Field(dn)
            if name in FIELD_ALIASES:
                assert dn == FIELD_ALIASES[name], f"{name} already maps to {FIELD_ALIASES[name]}"
            else:
                FIELD_ALIASES[name] = dn

    class _JIRA(JIRA):

        @locking_cache
        def fields(self):
            """Return a list of all issue fields."""
            return super().fields()

    @safe_property
    @synchronized
    def _CLIENT(self):
        client = self.__CLIENT
        if client and client._timer.expired:
            _logger.debug(
                f"JIRA client for '{self.url}' has expired "
                f"({client._timer.elapsed!r}>{self._CLIENT_EXPIRATION})")
            client = None

        if not client:
            user, token = self.login
            with _logger.indented(f"Connecting to {self.url}...", level=logging.DEBUG):
                options = dict(server=self.url, verify=certifi.where())
                client = self._JIRA(options=options, basic_auth=(user, token), timeout=DEFAULT_TIMEOUT, get_server_info=False)
                client._timer = Timer(expiration=self._CLIENT_EXPIRATION)
                _logger.debug(f"Client will expire in {client._timer.remain!r}")
                self.__CLIENT = client
                # only admins are allowed to suppress notifications for issue updates (notify=False)
                self.suppressable_notifications = True
        return client

    def _fetch_meta(self):
        meta = self._CLIENT.createmeta(
            projectKeys=",".join(self.REGISTRY.keys()),
            issuetypeNames=",".join(key for p in self.REGISTRY.values() for key in p.keys()),
            expand="projects.issuetypes.fields")
        projects = meta.get('projects', None)
        if not projects:
            raise LoginException(
                "User has no permissions",
                url=self.url,
                username=self.login[0]
            )

        for project_data in projects:
            project_key = project_data['key']
            _logger.info(f"{project_key}:")

            ns = dict(
                url=project_data['self'],
                id=project_data['id'],
                name=project_data['name'],
                key=project_data['key'],
                components=[],
                versions=[],
            )
            prj = type(project_key, (self.JiraProject,), ns)
            setattr(self, project_key, prj)

            for issuetype_data in project_data['issuetypes']:
                name = issuetype_data['name']
                _logger.info(f" - {name}")

                cls = self.REGISTRY[project_key][name]
                raw_fields = issuetype_data['fields']

                # for completeness, since these don't come from the JIRA createmeta API above
                for (field_id, f) in raw_fields.items():
                    key = f.get('name', field_id)
                    data = bunchify(f, field_id=field_id)
                    if key in self._meta:
                        assert self._meta[key] == data
                    else:
                        self._meta[key] = data

                issue_type = type(f"{project_key}.{name}", (cls,), dict(_CLIENT=self, project=prj, NAME=name))
                setattr(prj, name, issue_type)

                versions = bunchify({p['name']: p for p in raw_fields['fixVersions']['allowedValues']})
                if prj.versions:
                    assert prj.versions == versions
                else:
                    prj.versions = versions

                components = bunchify({p['name']: p for p in raw_fields['components']['allowedValues']})
                if prj.components:
                    assert prj.components == components
                else:
                    prj.components = components

        self._priorities = {p.name: i for i, p in enumerate(self._meta.Priority.allowedValues)}

    def _to_field(self, field_name):
        if field_name.startswith("_"):
            raise AttributeError(field_name)
        if field_name.isupper():
            raise AttributeError(field_name)

        try:
            spec = FIELD_ALIASES[field_name]
        except KeyError:
            raise UndefinedFieldException(f"{self} does not map field '{field_name}'", spec=None)

        try:
            return self._meta[spec.display_name]
        except KeyError as key:
            raise UndefinedFieldException(f"{self} could not find field '{key}' (mapped to {field_name})", spec=spec)

    def _to_field_id(self, field_name, safe=False):
        # when searching for issues, fields can be passed with '-' prefix, which causes
        # the REST to exclude these fields from the response
        # here we just want to make it convenient to the caller so he doesn't have to strip it
        _, prefix, field_name = field_name.rpartition("-")
        try:
            return prefix + self._to_field(field_name)['field_id']
        except UndefinedFieldException:
            if safe:
                return prefix + field_name
            raise

    def _to_field_value(self, field_name, value, update_mode=False):
        if field_name == "comment":
            return field_name, value

        field = self._to_field(field_name)
        field_type = field['schema']['type']
        is_array = field_type == "array"
        custom_type = field['schema'].get('custom', '')

        def to_value(value):
            if value is None:
                return value
            if field_type == 'string':
                return trim(value, MAX_TEXT_LENGTH)
            if field_type == 'number':
                return value
            if field_type in ('user', 'priority', 'obj', 'version', 'component'):
                return dict(name=value)
            if field_type == 'option':
                return dict(value=value)
            if field_type == 'datetime':
                return to_jira_time(value)
            if custom_type.endswith("cascadingselect"):
                values = value if hasattr(value, "__iter__") else [value]
                value = current = {}
                for elem in values[:-1]:
                    current.update(value=elem)
                    current = current.setdefault('child', {})
                current.update(value=values[-1])
                return value
            if custom_type.endswith("select"):
                return dict(value=value)
            return value

        if is_array:
            field_type = field['schema']['items']
            values = value if iterable(value) else [value]
            value = [to_value(v) for v in values]
            if update_mode:
                value = [dict(set=value)]
        elif isinstance(value, dict):
            pass
        else:
            value = to_value(value)

        return field['field_id'], value

    @classmethod
    def _to_value_id(cls, field_name, value, rigid=True):
        field = cls._to_field(field_name)
        allowed = {v.get('value') or v.get('name'): v['id']
                   for v in field['allowedValues']}
        if value in allowed:
            return allowed[value]
        found = [v for v in sorted(allowed)
                 if (v.startswith(value) if rigid else (value.lower() in v.lower()))]
        if not found:
            raise Exception(f"{value!r} is invalid for '{field_name}' (allowed: {', '.join(sorted(allowed))})")
        elif len(found) > 1:
            raise Exception(f"{value!r} is ambiguous for '{field_name}' (found: {', '.join(found)})")
        else:
            return allowed[found[0]]

    def get_filter_by_id(self, filter_id):
        return self._CLIENT.filter(filter_id)

    def update_filter_by_id(self, filter_id, name=None, jql=None, description=None):
        return self._CLIENT.update_filter(filter_id=filter_id, name=name, jql=jql, description=description)

    def get_filter_by_name(self, filter_name):
        '''
        get filter by its name, be careful with names as the search is the jira fuzzy search and may return multiple matches
        '''
        from jira.utils import json_loads
        client = self._CLIENT
        headers = client._session.headers
        url = self._CLIENT.url + "/rest/api/3/filter/search"
        filtered = client._session.get(url=url, headers=headers, params={"filterName": "\"%s\"" % filter_name})
        items = json_loads(filtered)
        for item in items['values']:
            if item['name'] == filter_name:
                return item['id']
        raise JiraException("Filter not found", filter_name=filter_name)

    def create_filter(self, name, jql, description=None):
        client = self._CLIENT
        headers = client._session.headers
        description = description or name  # lower level issue with empty description on update
        filt = client.create_filter(name=name, jql=jql, description=description)
        filter_id = filt.id
        url = self._CLIENT.url + f"/rest/api/3/filter/{filter_id}/permission"
        client._session.post(url=url, headers=headers, data='{"type": "group", "groupname": "jira-users"}')
        return filt

    def update_or_create_filter(self, name, jql):
        try:
            filter_id = self.get_filter_by_name(name)
            filt = self.update_filter_by_id(filter_id=filter_id, name=name, jql=jql)
            text = "Updated"
        except JiraException:
            filt = self.create_filter(name=name, jql=jql)
            text = "Created"
        _logger.debug(f"{text} filter: {name}, id: {filt.id}")
        return filt

    def rank(self, key, next_key):
        self._CLIENT.rank(key, next_key)

    def _to_issue(self, jira_issue, **kwargs):
        if project := getattr(self, jira_issue.key.split("-", 1)[0], None):
            if issue_type := getattr(project, jira_issue.fields.issuetype.name, None):
                return issue_type(jira_issue, **kwargs)
        return self.GenericIssue(jira_issue, **kwargs)

    def search_issues(self, *args, auto_refresh=False, **kwargs):
        issues = self._CLIENT.search_issues(*args, **kwargs)
        issues[:] = [self._to_issue(issue, auto_refresh=auto_refresh) for issue in issues]
        return issues

    def get_issue(self, key, **kwargs):
        return self._to_issue(self._CLIENT.issue(key, **kwargs))

    def get_many_by_keys(self, issue_keys, **kwargs):
        chunks = chunkify(issue_keys, 50)
        for chunk in chunks:
            yield from self.get_many(jql=f"key in ({', '.join(chunk)})", **kwargs)

    def get_by_summary(self, summary, limit=1, **kw):
        for ret in self.get_many(summary=("~", summary), limit=limit, **kw):
            return ret

    def get(self, issue_id, comments=False, fields=None, expand=None, auto_refresh=False):

        if fields is False:
            fields = "summary"
        elif fields is None:
            fields = []
        else:
            fields = fields[:]

        fields = [self._to_field_id(f, safe=True) for f in ilistify(fields)]
        if comments:
            fields.append("comment")
        else:
            fields.append("-comment")

        with resilience.info(
                "Supressing {type} ({exc.status_code}): {exc.text}", acceptable=JIRAError,
                pred=lambda exc: exc.status_code == 404 and "Issue does not exist" in exc.text):
            jira_issue = self._CLIENT.issue(issue_id, fields=fields, expand=expand)
            if jira_issue:
                return self._to_issue(jira_issue, auto_refresh=auto_refresh)

    def from_raw_issues(self, raw_issues):
        client = self._CLIENT
        issues = [
            self._to_issue(_JiraIssue(client._options, client._session, raw=raw))
            for raw in ilistify(raw_issues)]
        return issues if iterable(raw_issues) else issues[0]
