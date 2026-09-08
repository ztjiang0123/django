from itertools import chain

from django.apps import apps
from django.conf import settings
from django.core import checks
from django.utils.module_loading import import_string

from .management import _get_builtin_permissions


def _subclass_index(class_path, candidate_paths):
    """
    Return the index of dotted class path (or a subclass of that class) in a
    list of candidate paths. If it does not exist, return -1.
    """
    cls = import_string(class_path)
    for index, path in enumerate(candidate_paths):
        try:
            candidate_cls = import_string(path)
            if issubclass(candidate_cls, cls):
                return index
        except (ImportError, TypeError):
            continue
    return -1


def check_user_model(app_configs, **kwargs):
    if app_configs is None:
        cls = apps.get_model(settings.AUTH_USER_MODEL)
    else:
        app_label, model_name = settings.AUTH_USER_MODEL.split(".")
        for app_config in app_configs:
            if app_config.label == app_label:
                cls = app_config.get_model(model_name)
                break
        else:
            # Checks might be run against a set of app configs that don't
            # include the specified user model. In this case we simply don't
            # perform the checks defined below.
            return []

    errors = []

    # Check that REQUIRED_FIELDS is a list
    if not isinstance(cls.REQUIRED_FIELDS, (list, tuple)):
        errors.append(
            checks.Error(
                "'REQUIRED_FIELDS' must be a list or tuple.",
                obj=cls,
                id="auth.E001",
            )
        )

    # Check that the USERNAME FIELD isn't included in REQUIRED_FIELDS.
    if cls.USERNAME_FIELD in cls.REQUIRED_FIELDS:
        errors.append(
            checks.Error(
                "The field named as the 'USERNAME_FIELD' "
                "for a custom user model must not be included in 'REQUIRED_FIELDS'.",
                hint=(
                    "The 'USERNAME_FIELD' is currently set to '%s', you "
                    "should remove '%s' from the 'REQUIRED_FIELDS'."
                    % (cls.USERNAME_FIELD, cls.USERNAME_FIELD)
                ),
                obj=cls,
                id="auth.E002",
            )
        )

    # Check that the username field is unique
    if not cls._meta.get_field(cls.USERNAME_FIELD).unique and not any(
        constraint.fields == (cls.USERNAME_FIELD,)
        for constraint in cls._meta.total_unique_constraints
    ):
        if settings.AUTHENTICATION_BACKENDS == [
            "django.contrib.auth.backends.ModelBackend"
        ]:
            errors.append(
                checks.Error(
                    "'%s.%s' must be unique because it is named as the "
                    "'USERNAME_FIELD'." % (cls._meta.object_name, cls.USERNAME_FIELD),
                    obj=cls,
                    id="auth.E003",
                )
            )
        else:
            errors.append(
                checks.Warning(
                    "'%s.%s' is named as the 'USERNAME_FIELD', but it is not unique."
                    % (cls._meta.object_name, cls.USERNAME_FIELD),
                    hint=(
                        "Ensure that your authentication backend(s) can handle "
                        "non-unique usernames."
                    ),
                    obj=cls,
                    id="auth.W004",
                )
            )

    if callable(cls().is_anonymous):
        errors.append(
            checks.Critical(
                "%s.is_anonymous must be an attribute or property rather than "
                "a method. Ignoring this is a security issue as anonymous "
                "users will be treated as authenticated!" % cls,
                obj=cls,
                id="auth.C009",
            )
        )
    if callable(cls().is_authenticated):
        errors.append(
            checks.Critical(
                "%s.is_authenticated must be an attribute or property rather "
                "than a method. Ignoring this is a security issue as anonymous "
                "users will be treated as authenticated!" % cls,
                obj=cls,
                id="auth.C010",
            )
        )
    return errors


class _ModelPermissionChecker:
    """Collect permission-related check errors for a single model."""

    def __init__(self, model, name_max_length, codename_max_length):
        self.model = model
        self.opts = model._meta
        self.name_max_length = name_max_length
        self.codename_max_length = codename_max_length
        self.builtin_permissions = dict(_get_builtin_permissions(self.opts))

    def check(self):
        """Run all permission checks and return the collected errors."""
        errors = self._check_builtin_name_length()
        errors += self._check_builtin_codename_length()
        errors += self._check_custom_permissions()
        return errors

    def _check_builtin_name_length(self):
        if not self.builtin_permissions:
            return []
        max_length = max(len(name) for name in self.builtin_permissions.values())
        if max_length <= self.name_max_length:
            return []
        verbose_name_max_length = self.name_max_length - (
            max_length - len(self.opts.verbose_name_raw)
        )
        return [
            checks.Error(
                "The verbose_name of model '%s' must be at most %d "
                "characters for its builtin permission names to be at "
                "most %d characters."
                % (self.opts.label, verbose_name_max_length, self.name_max_length),
                obj=self.model,
                id="auth.E007",
            )
        ]

    def _check_builtin_codename_length(self):
        if not self.builtin_permissions:
            return []
        max_length = max(len(codename) for codename in self.builtin_permissions)
        if max_length <= self.codename_max_length:
            return []
        model_name_max_length = self.codename_max_length - (
            max_length - len(self.opts.model_name)
        )
        return [
            checks.Error(
                "The name of model '%s' must be at most %d characters "
                "for its builtin permission codenames to be at most %d "
                "characters."
                % (self.opts.label, model_name_max_length, self.codename_max_length),
                obj=self.model,
                id="auth.E011",
            )
        ]

    def _check_custom_permissions(self):
        errors = []
        seen_codenames = set()
        for codename, name in self.opts.permissions:
            errors += self._check_custom_permission(codename, name, seen_codenames)
            seen_codenames.add(codename)
        return errors

    def _check_custom_permission(self, codename, name, seen_codenames):
        """Check a single custom permission for length and clashing issues."""
        errors = []
        # Check custom permission name length.
        if len(name) > self.name_max_length:
            errors.append(
                checks.Error(
                    "The permission named '%s' of model '%s' is longer "
                    "than %d characters."
                    % (name, self.opts.label, self.name_max_length),
                    obj=self.model,
                    id="auth.E008",
                )
            )
        # Check custom permission codename length.
        if len(codename) > self.codename_max_length:
            errors.append(
                checks.Error(
                    "The permission codenamed '%s' of model '%s' is "
                    "longer than %d characters."
                    % (codename, self.opts.label, self.codename_max_length),
                    obj=self.model,
                    id="auth.E012",
                )
            )
        # Check custom permissions codename clashing.
        if codename in self.builtin_permissions:
            errors.append(
                checks.Error(
                    "The permission codenamed '%s' clashes with a builtin "
                    "permission for model '%s'." % (codename, self.opts.label),
                    obj=self.model,
                    id="auth.E005",
                )
            )
        elif codename in seen_codenames:
            errors.append(
                checks.Error(
                    "The permission codenamed '%s' is duplicated for "
                    "model '%s'." % (codename, self.opts.label),
                    obj=self.model,
                    id="auth.E006",
                )
            )
        return errors


def check_models_permissions(app_configs, **kwargs):
    if app_configs is None:
        models = apps.get_models()
    else:
        models = chain.from_iterable(
            app_config.get_models() for app_config in app_configs
        )

    Permission = apps.get_model("auth", "Permission")
    permission_name_max_length = Permission._meta.get_field("name").max_length
    permission_codename_max_length = Permission._meta.get_field("codename").max_length
    errors = []

    for model in models:
        errors += _ModelPermissionChecker(
            model, permission_name_max_length, permission_codename_max_length
        ).check()

    return errors


def check_middleware(app_configs, **kwargs):
    errors = []

    login_required_index = _subclass_index(
        "django.contrib.auth.middleware.LoginRequiredMiddleware",
        settings.MIDDLEWARE,
    )

    if login_required_index != -1:
        auth_index = _subclass_index(
            "django.contrib.auth.middleware.AuthenticationMiddleware",
            settings.MIDDLEWARE,
        )
        if auth_index == -1 or auth_index > login_required_index:
            errors.append(
                checks.Error(
                    "In order to use django.contrib.auth.middleware."
                    "LoginRequiredMiddleware, django.contrib.auth.middleware."
                    "AuthenticationMiddleware must be defined before it in MIDDLEWARE.",
                    id="auth.E013",
                )
            )
    return errors
