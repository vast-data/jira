import sys
import json
import time
from traceback import format_exception
import logging

import dateutil.parser

from itertools import chain

from jira import JIRAError, Issue as _JiraIssue
import jira.resources
import jira.exceptions

from easypy.resilience import resilience
from easypy.units import Duration
from easypy.collections import ilistify, listify, iterable
from easypy.tokens import NOT_FOUND, NO_DEFAULT, AUTO, ALL, if_auto
from easypy.properties import safe_property
from .client import JiraClient, Field, JiraException, UndefinedFieldException
from .common import clean, noformatted, trim, squeeze_summary, MAX_TEXT_LENGTH, MAX_COMMENT_LENGTH

######################
# exceptions
######################


class InvalidTransitionException(JiraException):
    pass


class IssueNotFound(JiraException):
    pass


class TransitionError(JiraException):
    pass


_logger = logging.getLogger(__name__)


LINK_DIRECTIONS = dict()
for alias in 'i in inward >'.split():
    LINK_DIRECTIONS[alias] = "inwardIssue"
for alias in 'o out outward <'.split():
    LINK_DIRECTIONS[alias] = "outwardIssue"


class IssueMeta(type):

    @safe_property
    def NAME(cls):
        return cls.__dict__.get('NAME', cls.__name__)


class GenericIssue(object, metaclass=IssueMeta):

    # Project key in Jira
    PROJECT = ''

    # map python identifiers to jira fields
    FIELDS = {}

    # list of fields to include in fetch requests
    DEFAULT_FETCH_FIELDS = ALL

    # reserved
    _CLIENT = None    # pointer to a JiraClient instance
    project = None    # pointer to a JiraProject instance

    Field = Field  # used by subclasses to define fields with further cusomizations

    def __init_subclass__(cls):
        JiraClient.register(cls)

    def __init__(self, jira_issue, auto_refresh=False):
        self._issue = jira_issue
        self._auto_refresh = auto_refresh

    def __repr__(self):
        return f"{self.__class__.__name__}(<{self.key}>)"

    def __str__(self):
        return f"<{self.url}>"

    def refresh(self):
        self.__init__(self.get(self.key)._issue)

    @safe_property
    def _multiobject_log_ctx(self):
        return dict(host=self.key)

    @safe_property
    def key(self):
        return self._issue.key

    id = key

    def __hash__(self):
        return hash(self.key)

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return self.key == other.key

    @safe_property
    def issue_type(self):
        return self._issue.fields.issuetype.name

    @safe_property
    def url(self):
        return f"{self._CLIENT.url}/browse/{self.key}"

    def _do_transition(self, transition, comment=None, comment_on_exception=True, **fields):

        def do_it(fields):
            return self._CLIENT.transition_issue(issue=self.key, transition=transition, comment=comment, fields=fields)

        if comment:
            comment = trim(comment, MAX_TEXT_LENGTH)  # the comment max here is 32Kb
        fields = dict(self._CLIENT._to_field_value(*p) for p in fields.items())

        try:
            do_it(fields)
        except Exception as exc:
            _logger.silent_exception(f"Could not transition to {transition}")
            if comment_on_exception:
                with resilience.warning():
                    traceback = "".join(format_exception(*sys.exc_info()))
                    self.add_comment(f"Could not transition to {transition}\n{noformatted(traceback, MAX_COMMENT_LENGTH)}")

            if isinstance(exc, JIRAError) and exc.response:
                # We try to raise a sane exception
                # If we fail we raise the original
                with resilience.error(unacceptable=TransitionError):
                    self.refresh()
                    response_text = exc.response.text
                    response = json.loads(response_text)
                    raise TransitionError(
                        f"Could not transition {self.key} to {transition}: {exc.text}",
                        issue_key=self.key, errors=response['errorMessages'], status=self.status, **response.get('errors')
                    ) from exc

            raise

    @classmethod
    def create(cls, summary=None, description=None, components=None, labels=None, comments=None, links=None, **fields):

        params = dict(cls._CLIENT._to_field_value(*p) for p in fields.items())
        params.update(
            project=dict(id=cls.project.id),
            issuetype=dict(name=cls.NAME),
        )
        if summary:
            params['summary'] = squeeze_summary(summary)
        if description:
            params['description'] = trim(description, MAX_TEXT_LENGTH)
        if labels:
            params['labels'] = labels
        if links:
            params['raw'] = dict(update=dict(issuelinks=[dict(
                add=dict(
                    type=dict(name=typ),
                    **{LINK_DIRECTIONS.get(direction.lower(), direction): dict(key=key)}
                )) for (typ, direction, key) in links
            ]))

        ret = cls(cls._CLIENT.create_issue(**params))
        for comment in comments or []:
            ret.add_comment(comment)
        return ret

    @classmethod
    def get_many(
            cls, jql=None, limit=None, page_size=50, order_by=None, fields=AUTO,
            expand=None, comments=False, auto_refresh=False, **kwargs):

        if limit:
            page_size = min(limit, page_size)

        criteria = [
            f"project = {cls.PROJECT}",
            f"issuetype = {cls.NAME}",
        ]

        for field_name, value in kwargs.items():
            field = cls._CLIENT._to_field(field_name)

            if isinstance(value, tuple):
                op, value = value
            elif value is None:
                _logger.debug("Ignoring '%s' because value is None. Use ('=', None) to get EMPTY fields",
                              field_name)
                continue
            elif 'schema' in field and field['schema']['type'] == 'string':
                op = "~"
                value = f'\\"{value}\\"'
            else:
                op = "="

            def normalize(value):
                if iterable(value):
                    return "(%s)" % ", ".join(normalize(v) for v in value)
                elif value is None:
                    return "EMPTY"
                else:
                    return f'"{value}"'

            value = normalize(value)
            field_name = field['name']
            criteria.append(f'"{field_name}" {op} {value}')

        if jql:
            criteria.append(jql)

        jql = " AND ".join(criteria)
        if order_by:
            jql += f" ORDER BY {', '.join(listify(order_by))}"
        _logger.debug(f"JQL: '{jql}', page-size={page_size}")

        fields = if_auto(fields, cls.DEFAULT_FETCH_FIELDS)
        if fields is False:
            fields = "summary"
        elif fields is ALL:
            fields = []

        fields = [cls._CLIENT._to_field_id(f, safe=True) for f in listify(fields)]
        if comments:
            fields.append("comment")
        else:
            fields.append("-comment")

        def get_results(start_at):
            return cls._CLIENT.search_issues(
                jql, startAt=start_at, maxResults=page_size,
                fields=fields, expand=expand, validate_query=False)

        i = 0
        while True:
            results = get_results(i)
            if i == 0:
                # adjust the limit according to actual results
                limit = min(results.total if limit is None else limit, results.total)
                if limit > 100:
                    # let us know when there's lots of issues to fetch
                    _logger.info(f"fetching {limit} issues from jira...")
            # using zip to both count and limit the results yielded
            for i, jira_issue in zip(range(i, limit), results):
                yield jira_issue
            i += 1  # this is how many where actually yielded so far
            if i >= limit:
                return
            _logger.debug(f"({i} out of {limit})")

    @classmethod
    def get(cls, *args, fields=AUTO, **kwargs):
        fields = if_auto(fields, cls.DEFAULT_FETCH_FIELDS)
        return cls._CLIENT.get(*args, fields=fields, **kwargs)

    def from_raw_issues(self, raw_issues):
        client = self._CLIENT
        issues = [
            self.__class__(_JiraIssue(client._options, client._session, raw=raw))
            for raw in ilistify(raw_issues)]
        return issues if iterable(raw_issues) else issues[0]

    # lower level  ^
    #              |
    # =============:=============================================
    #              |
    # higher level v

    @safe_property
    def priority_level(self):
        return self._CLIENT._priorities[self.priority]

    @safe_property
    def resolved(self):
        return dateutil.parser.parse(self._issue.fields.resolutiondate) if self._issue.fields.resolutiondate else None

    @safe_property
    def since_resolved(self):
        return Duration(time.time() - self.resolved.timestamp()) if self.resolved else float('-inf')

    @safe_property
    def since_updated(self):
        return Duration(time.time() - self.updated.timestamp())

    @safe_property
    def since_created(self):
        return Duration(time.time() - self.created.timestamp())

    def __getattr__(self, field_name):

        if field_name.startswith("is_"):
            status_name = field_name[3:]
            status = getattr(self.STATUS, status_name.upper(), None)
            if not status:
                raise JiraException("No such status", issue=self.key, status=status_name)
            return self.status == status

        try:
            field = self._CLIENT._to_field(field_name)
        except UndefinedFieldException as exc:
            if not exc.spec:
                raise
            if exc.spec.default is NO_DEFAULT:
                raise
            return exc.spec.default

        schema = field['schema']
        field_type = schema['type']

        value = getattr(self._issue.fields, field['field_id'], NOT_FOUND)
        if value is NOT_FOUND:
            value = (
                0 if field_type == 'number' else
                '' if field_type == 'string' else
                [] if field_type == 'array' else
                None)

        return self._normalize_field_value(field_type, value, schema)

    def _normalize_field_value(self, typ, value, schema=None):
        if isinstance(value, jira.resources.CustomFieldOption):
            return value.value
        if isinstance(value, jira.resources.User):
            return value.emailAddress
        if isinstance(value, jira.resources.Resource):
            return value.name
        if typ == 'string':
            return clean(value or '')  # ensure we get a string and not None
        if typ == 'date':
            return dateutil.parser.parse(value)
        if typ == 'array':
            if not value:
                return []
            return [self._normalize_field_value(schema['items'], v) for v in value]
        return value

    def __dir__(self):
        return sorted(set(chain(dir(self.__class__), self.__dict__, self.FIELDS)))

    def _maybe_auto_refresh(self, auto_refresh):
        auto_refresh = auto_refresh if isinstance(auto_refresh, bool) else self._auto_refresh
        if auto_refresh:
            self.refresh()
            return True

    def update(self, *, notify=False, auto_refresh=None, raw_update=None, comment=None, **fields):
        notify = notify if self._CLIENT.suppressable_notifications else True
        fields = dict(self._CLIENT._to_field_value(*p, update_mode=True) for p in fields.items())
        if comment:
            fields.update(comment=comment)
        if raw_update:
            raw_update = {self._CLIENT._to_field_id(k): v for k, v in raw_update.items()}
        self._issue.update(update=raw_update, notify=notify, **fields)
        if self._maybe_auto_refresh(auto_refresh):
            return self

    def get_comments(self):
        return self._CLIENT.comments(self.key)

    def add_comment(self, comment, *args):
        if args:
            comment %= args
        client = self._CLIENT
        comment = trim(comment, MAX_COMMENT_LENGTH)
        try:
            client.add_comment(self.key, comment)
        except UnicodeError as e:
            _logger.exception("Error while adding comment")
            client.add_comment(self.key, f"(comment could not be added - {e})")

    def add_labels(self, *labels, notify=False, comment=None):
        kw = {}
        if comment:
            kw.update(comment=comment)
        self.update(raw_update=dict(labels=[dict(add=value) for value in labels]), notify=notify, **kw)

    def remove_labels(self, *labels, notify=False, comment=None):
        kw = {}
        if comment:
            kw.update(comment=comment)
        self.update(raw_update=dict(labels=[dict(remove=value) for value in labels]), notify=notify, **kw)

    def set_version(self, *versions):
        self.update(raw_update=dict(versions=[dict(set=[dict(name=v) for v in versions])]))

    def set_assignee(self, assignee, auto_refresh=None):
        if "@" not in assignee:
            assignee += "@vastdata.com"
        self._CLIENT.assign_issue(self.key, assignee)
        self._maybe_auto_refresh(auto_refresh)

    def do_transition(self, transition, comment=None, data=None, auto_refresh=None, **fields):
        self._do_transition(transition, comment=comment, **fields)
        if data:
            self.update(auto_refresh=auto_refresh, **data)  # also refreshes
        else:
            self._maybe_auto_refresh(auto_refresh)

    def add_link(self, to_issues, link_type, comment=None, invert=False, notify=False, auto_refresh=None):
        direction = "inwardIssue" if invert else "outwardIssue"
        # we have to do this with several requests, due to:
        # https://jira.atlassian.com/browse/JRACLOUD-65583
        # otherwise we'd put all links in this list
        for issue in listify(to_issues):
            issuelinks = [dict(add={
                "type": dict(name=link_type),
                direction: dict(key=getattr(issue, "key", issue))})]
            self.update(raw_update=dict(issuelinks=issuelinks), notify=notify)

        self._maybe_auto_refresh(auto_refresh)

    def iter_linked_issues(self, link_type):
        for link in self._issue.fields.issuelinks:
            if link_type and link.type.name != link_type:
                continue
            for direction in ("inward", "outward"):
                jira_issue = getattr(link, f"{direction}Issue", None)
                if jira_issue:
                    yield self._CLIENT._to_issue(jira_issue)

    def get_change_log(self):
        jira_issue = self._CLIENT.issue(self.key, expand="changelog")
        return [{f.field: f for f in record.items} for record in jira_issue.changelog.histories]

    def delete(self):
        self._issue.delete()
