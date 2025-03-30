# Configuration and options dataclasses.

from __future__ import annotations

import sys
from dataclasses import field
from typing import TYPE_CHECKING, Annotated, Any, Literal

from mkdocstrings import get_logger

# YORE: EOL 3.10: Replace block with line 2.
if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


_logger = get_logger(__name__)


try:
    # When Pydantic is available, use it to validate options (done automatically).
    # Users can therefore opt into validation by installing Pydantic in development/CI.
    # When building the docs to deploy them, Pydantic is not required anymore.

    # When building our own docs, Pydantic is always installed (see `docs` group in `pyproject.toml`)
    # to allow automatic generation of a JSON Schema. The JSON Schema is then referenced by mkdocstrings,
    # which is itself referenced by mkdocs-material's schema system. For example in VSCode:
    #
    # "yaml.schemas": {
    #     "https://squidfunk.github.io/mkdocs-material/schema.json": "mkdocs.yml"
    # }
    import pydantic

    if getattr(pydantic, "__version__", "1.").startswith("1."):
        raise ImportError  # noqa: TRY301

    # YORE: EOL 3.9: Remove block.
    if sys.version_info < (3, 10):
        try:
            import eval_type_backport  # noqa: F401
        except ImportError:
            _logger.debug(
                "Pydantic needs the `eval-type-backport` package to be installed "
                "for modern type syntax to work on Python 3.9. "
                "Deactivating Pydantic validation for Sh handler options.",
            )
            raise

    from inspect import cleandoc

    from pydantic import Field as BaseField
    from pydantic.dataclasses import dataclass

    _base_url = "https://mkdocstrings.github.io/mkdocstrings-sh/usage"

    def _Field(  # noqa: N802
        *args: Any,
        description: str,
        group: Literal["general"] | None = None,
        parent: str | None = None,
        **kwargs: Any,
    ) -> None:
        def _add_markdown_description(schema: dict[str, Any]) -> None:
            url = f"{_base_url}/{f'configuration/{group}/' if group else ''}#{parent or schema['title']}"
            schema["markdownDescription"] = f"[DOCUMENTATION]({url})\n\n{schema['description']}"

        return BaseField(
            *args,
            description=cleandoc(description),
            field_title_generator=lambda name, _: name,
            json_schema_extra=_add_markdown_description,
            **kwargs,
        )
except ImportError:
    from dataclasses import dataclass

    def _Field(*args: Any, **kwargs: Any) -> None:  # type: ignore[misc]  # noqa: N802
        pass


if TYPE_CHECKING:
    from collections.abc import MutableMapping


# YORE: EOL 3.9: Remove block.
_dataclass_options = {"frozen": True}
if sys.version_info >= (3, 10):
    _dataclass_options["kw_only"] = True


# The input config class is useful to generate a JSON schema, see scripts/mkdocs_hooks.py.
# YORE: EOL 3.9: Replace `**_dataclass_options` with `frozen=True, kw_only=True` within line.
@dataclass(**_dataclass_options)
class ShInputOptions:
    """Accepted input options."""

    extra: Annotated[
        dict[str, Any],
        _Field(
            group="general",
            description="Extra options.",
        ),
    ] = field(default_factory=dict)

    heading: Annotated[
        str,
        _Field(
            group="headings",
            description="A custom string to override the autogenerated heading of the root object.",
        ),
    ] = ""

    heading_level: Annotated[
        int,
        _Field(
            group="headings",
            description="The initial heading level to use.",
        ),
    ] = 2

    show_symbol_type_heading: Annotated[
        bool,
        _Field(
            group="headings",
            description="Show the symbol type in headings (e.g. mod, class, meth, func and attr).",
        ),
    ] = False

    show_symbol_type_toc: Annotated[
        bool,
        _Field(
            group="headings",
            description="Show the symbol type in the Table of Contents (e.g. mod, class, methd, func and attr).",
        ),
    ] = False

    toc_label: Annotated[
        str,
        _Field(
            group="headings",
            description="A custom string to override the autogenerated toc label of the root object.",
        ),
    ] = ""

    @classmethod
    def coerce(cls, **data: Any) -> MutableMapping[str, Any]:
        """Coerce data."""
        return data

    @classmethod
    def from_data(cls, **data: Any) -> Self:
        """Create an instance from a dictionary."""
        return cls(**cls.coerce(**data))


# YORE: EOL 3.9: Replace `**_dataclass_options` with `frozen=True, kw_only=True` within line.
@dataclass(**_dataclass_options)
class ShOptions(ShInputOptions):  # type: ignore[override,unused-ignore]
    """Final options passed as template context."""

    # Re-declare any field to modify/narrow its type.

    @classmethod
    def coerce(cls, **data: Any) -> MutableMapping[str, Any]:
        """Create an instance from a dictionary."""
        # Coerce any field into its final form.
        return super().coerce(**data)


# The input config class is useful to generate a JSON schema, see scripts/mkdocs_hooks.py.
# YORE: EOL 3.9: Replace `**_dataclass_options` with `frozen=True, kw_only=True` within line.
@dataclass(**_dataclass_options)
class ShInputConfig:
    """Sh handler configuration."""

    # We want to validate options early, so we load them as `ShInputOptions`.
    options: Annotated[
        ShInputOptions,
        _Field(description="Configuration options for collecting and rendering objects."),
    ] = field(default_factory=ShInputOptions)

    @classmethod
    def coerce(cls, **data: Any) -> MutableMapping[str, Any]:
        """Coerce data."""
        return data

    @classmethod
    def from_data(cls, **data: Any) -> Self:
        """Create an instance from a dictionary."""
        return cls(**cls.coerce(**data))


# YORE: EOL 3.9: Replace `**_dataclass_options` with `frozen=True, kw_only=True` within line.
@dataclass(**_dataclass_options)
class ShConfig(ShInputConfig):  # type: ignore[override,unused-ignore]
    """Sh handler configuration."""

    # We want to keep a simple dictionary in order to later merge global and local options.
    options: dict[str, Any] = field(default_factory=dict)  # type: ignore[assignment]
    """Global options in mkdocs.yml."""

    @classmethod
    def coerce(cls, **data: Any) -> MutableMapping[str, Any]:
        """Coerce data."""
        return super().coerce(**data)
