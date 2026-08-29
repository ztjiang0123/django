import json

from django.conf import settings
from django.contrib.admin.utils import quote
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.urls import NoReverseMatch, reverse
from django.utils import timezone
from django.utils.text import get_text_list
from django.utils.translation import gettext
from django.utils.translation import gettext_lazy as _

ADDITION = 1
CHANGE = 2
DELETION = 3

ACTION_FLAG_CHOICES = [
    (ADDITION, _("Addition")),
    (CHANGE, _("Change")),
    (DELETION, _("Deletion")),
]


class LogEntryManager(models.Manager):
    use_in_migrations = True

    def log_actions(
        self, user_id, queryset, action_flag, change_message="", *, single_object=False
    ):
        if isinstance(change_message, list):
            change_message = json.dumps(change_message)

        log_entry_list = [
            self.model(
                user_id=user_id,
                content_type_id=ContentType.objects.get_for_model(
                    obj, for_concrete_model=False
                ).id,
                object_id=obj.pk,
                object_repr=str(obj)[:200],
                action_flag=action_flag,
                change_message=change_message,
            )
            for obj in queryset
        ]

        if len(log_entry_list) == 1:
            instance = log_entry_list[0]
            instance.save()
            if single_object:
                return instance
            return [instance]

        return self.model.objects.bulk_create(log_entry_list)


class LogEntry(models.Model):
    action_time = models.DateTimeField(
        _("action time"),
        default=timezone.now,
        editable=False,
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        models.CASCADE,
        verbose_name=_("user"),
    )
    content_type = models.ForeignKey(
        ContentType,
        models.SET_NULL,
        verbose_name=_("content type"),
        blank=True,
        null=True,
    )
    object_id = models.TextField(_("object id"), blank=True, null=True)
    # Translators: 'repr' means representation
    # (https://docs.python.org/library/functions.html#repr)
    object_repr = models.CharField(_("object repr"), max_length=200)
    action_flag = models.PositiveSmallIntegerField(
        _("action flag"), choices=ACTION_FLAG_CHOICES
    )
    # change_message is either a string or a JSON structure
    change_message = models.TextField(_("change message"), blank=True)

    objects = LogEntryManager()

    class Meta:
        verbose_name = _("log entry")
        verbose_name_plural = _("log entries")
        db_table = "django_admin_log"
        ordering = ["-action_time"]

    def __repr__(self):
        return str(self.action_time)

    def __str__(self):
        if self.is_addition():
            return gettext("Added “%(object)s”.") % {"object": self.object_repr}
        elif self.is_change():
            return gettext("Changed “%(object)s” — %(changes)s") % {
                "object": self.object_repr,
                "changes": self.get_change_message(),
            }
        elif self.is_deletion():
            return gettext("Deleted “%(object)s.”") % {"object": self.object_repr}

        return gettext("LogEntry Object")

    def is_addition(self):
        return self.action_flag == ADDITION

    def is_change(self):
        return self.action_flag == CHANGE

    def is_deletion(self):
        return self.action_flag == DELETION

    @staticmethod
    def _format_added_message(added):
        if not added:
            return gettext("Added.")
        added["name"] = gettext(added["name"])
        return gettext("Added {name} “{object}”.").format(**added)

    @staticmethod
    def _format_changed_message(changed):
        changed["fields"] = get_text_list(
            [gettext(field_name) for field_name in changed["fields"]],
            gettext("and"),
        )
        if "name" not in changed:
            return gettext("Changed {fields}.").format(**changed)
        changed["name"] = gettext(changed["name"])
        return gettext("Changed {fields} for {name} “{object}”.").format(**changed)

    @staticmethod
    def _format_deleted_message(deleted):
        deleted["name"] = gettext(deleted["name"])
        return gettext("Deleted {name} “{object}”.").format(**deleted)

    def _format_sub_message(self, sub_message):
        """Return the translated string for a single change sub-message."""
        if "added" in sub_message:
            return self._format_added_message(sub_message["added"])
        if "changed" in sub_message:
            return self._format_changed_message(sub_message["changed"])
        if "deleted" in sub_message:
            return self._format_deleted_message(sub_message["deleted"])
        return None

    def get_change_message(self):
        """
        If self.change_message is a JSON structure, interpret it as a change
        string, properly translated.
        """
        if not (self.change_message and self.change_message[0] == "["):
            return self.change_message

        try:
            change_message = json.loads(self.change_message)
        except json.JSONDecodeError:
            return self.change_message

        messages = []
        for sub_message in change_message:
            message = self._format_sub_message(sub_message)
            if message is not None:
                messages.append(message)

        change_message = " ".join(msg[0].upper() + msg[1:] for msg in messages)
        return change_message or gettext("No fields changed.")

    def get_edited_object(self):
        """Return the edited object represented by this log entry."""
        return self.content_type.get_object_for_this_type(pk=self.object_id)

    def get_admin_url(self):
        """
        Return the admin URL to edit the object represented by this log entry.
        """
        if self.content_type and self.object_id:
            url_name = "admin:%s_%s_change" % (
                self.content_type.app_label,
                self.content_type.model,
            )
            try:
                return reverse(url_name, args=(quote(self.object_id),))
            except NoReverseMatch:
                pass
        return None
