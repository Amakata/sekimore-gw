"""lang/plan.py: which language images a pull request checks and a publish builds (#376)."""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("lang_plan", ROOT / "lang" / "plan.py")
plan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(plan)

HEAD = """
pin:
  php:
    "8.3.26": 1
    "8.3.33": 1
  python:
    "2.7.18": 1
"""


def e(lang, version, revision=1):
    return {"lang": lang, "version": version, "revision": revision}


def describe_versions_yml():
    def it_reads_each_version_with_its_revision():
        assert plan.entries(HEAD) == [e("php", "8.3.26"), e("php", "8.3.33"), e("python", "2.7.18")]

    @pytest.mark.parametrize(
        "text",
        [
            'pin:\n  php: ["8.3.26"]\n',  # the old list form: no revision
            'pin:\n  php:\n    "8.3.26": 0\n',
            'pin:\n  php:\n    "8.3.26": true\n',
            'pin:\n  php:\n    "latest": 1\n',
        ],
    )
    def it_refuses_what_is_not_a_version_and_a_revision(text):
        with pytest.raises(ValueError):
            plan.entries(text)

    def it_tags_with_the_revision():
        assert plan.tag(e("php", "8.3.33", 2)) == "8.3.33-2-bookworm"


def describe_a_pull_request():
    head = plan.entries(HEAD)
    base = [e("php", "8.3.26"), e("python", "2.7.18")]

    def it_checks_only_the_version_it_adds():
        assert plan.plan_pr(head, base, ["lang/versions.yml"]) == [e("php", "8.3.33")]

    def it_checks_a_raised_revision():
        raised = [e("php", "8.3.26", 2), e("php", "8.3.33"), e("python", "2.7.18")]
        assert plan.plan_pr(raised, head, ["lang/versions.yml"]) == [e("php", "8.3.26", 2)]

    def it_checks_the_newest_version_of_a_language_whose_recipe_changed():
        assert plan.plan_pr(head, head, ["lang/php/deps"]) == [e("php", "8.3.33")]

    def it_checks_every_language_when_the_common_recipe_changed():
        assert plan.plan_pr(head, head, ["lang/Dockerfile"]) == [
            e("php", "8.3.33"),
            e("python", "2.7.18"),
        ]

    def it_checks_nothing_for_a_change_that_builds_nothing():
        assert plan.plan_pr(head, head, ["lang/README.md", "docs/languages.md"]) == []


def describe_a_publish():
    head = plan.entries(HEAD)

    def it_builds_only_what_the_registry_lacks():
        on = {
            "ghcr.io/amakata/sgw-lang-php:8.3.26-1-bookworm",
            "ghcr.io/amakata/sgw-lang-python:2.7.18-1-bookworm",
        }
        assert plan.plan_publish(head, on.__contains__) == {
            "build": [e("php", "8.3.33")],
            "adopt": [],
        }

    def it_adopts_an_image_published_before_revisions_rather_than_rebuilding_it():
        on = {
            "ghcr.io/amakata/sgw-lang-php:8.3.26-bookworm",
            "ghcr.io/amakata/sgw-lang-python:2.7.18-bookworm",
        }
        assert plan.plan_publish(head, on.__contains__) == {
            "build": [e("php", "8.3.33")],
            "adopt": [e("php", "8.3.26"), e("python", "2.7.18")],
        }

    def it_rebuilds_a_raised_revision_even_where_the_moving_tag_exists():
        on = {
            "ghcr.io/amakata/sgw-lang-php:8.3.26-bookworm",
            "ghcr.io/amakata/sgw-lang-php:8.3.26-1-bookworm",
        }
        assert plan.plan_publish([e("php", "8.3.26", 2)], on.__contains__) == {
            "build": [e("php", "8.3.26", 2)],
            "adopt": [],
        }


def describe_a_base_branch_from_before_revisions():
    def it_reads_the_old_list_form_as_revision_1():
        old = 'pin:\n  php: ["8.3.26"]\n  python: ["2.7.18"]\n'
        base = plan.entries(old, before_revisions=True)
        assert base == [e("php", "8.3.26"), e("python", "2.7.18")]
        assert plan.plan_pr(plan.entries(HEAD), base, ["lang/versions.yml"]) == [e("php", "8.3.33")]
