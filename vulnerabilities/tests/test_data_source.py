#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
import xml.etree.ElementTree as ET
from unittest import TestCase
from unittest.mock import patch

import pytest
from fetchcode.vcs import VCSResponse
from packageurl import PackageURL

from vulnerabilities.importer import ForkError
from vulnerabilities.importer import GitImporter
from vulnerabilities.importer import OvalImporter
from vulnerabilities.oval_parser import OvalParser

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/")


def load_oval_data():
    etrees_of_oval = {}
    for f in os.listdir(TEST_DATA):
        if f.endswith("oval_data.xml"):
            path = os.path.join(TEST_DATA, f)
            provider = f.split("_")[0]
            etrees_of_oval[provider] = ET.parse(path)
    return etrees_of_oval


class SampleOvalImporter(OvalImporter):
    spdx_license_expression = "FOO-BAR"


class TestOvalImporter(TestCase):

    def test_create_purl(self):
        purl1 = PackageURL(name="ffmpeg", type="test", version="1.2.0")

        assert purl1 == SampleOvalImporter().create_purl(
            pkg_name="ffmpeg", pkg_version="1.2.0", pkg_data={"type": "test"}
        )

        purl2 = PackageURL(
            name="notepad",
            type="example",
            version="7.9.6",
            namespace="ns",
            qualifiers={"distro": "sample"},
            subpath="root",
        )
        assert purl2 == SampleOvalImporter().create_purl(
            pkg_name="notepad",
            pkg_version="7.9.6",
            pkg_data={
                "namespace": "ns",
                "qualifiers": {"distro": "sample"},
                "subpath": "root",
                "type": "example",
            },
        )

    def test__collect_pkgs(self):

        xmls = load_oval_data()

        expected_suse_pkgs = {"cacti-spine", "apache2-mod_perl", "cacti", "apache2-mod_perl-devel"}
        expected_ubuntu_pkgs = {"potrace", "tor"}

        translations = {"less than": "<"}

        found_suse_pkgs = SampleOvalImporter()._collect_pkgs(
            OvalParser(translations, xmls["suse"]).get_data()
        )

        found_ubuntu_pkgs = SampleOvalImporter()._collect_pkgs(
            OvalParser(translations, xmls["ubuntu"]).get_data()
        )

        assert found_suse_pkgs == expected_suse_pkgs
        assert found_ubuntu_pkgs == expected_ubuntu_pkgs

class TestGitImporter(TestCase):
    def test_clone_valid(self):
        with patch.object(GitImporter, "__init__", return_value=None):
            c = GitImporter(None)
            c.repo_url = "git+https://github.com/nexB/fetchcode"
            c.clone()
            self.assertIsInstance(c.vcs_response, VCSResponse)
            assert os.path.exists(c.vcs_response.dest_dir)
            assert c.vcs_response.vcs_type == 'git'
            assert c.vcs_response.domain == 'github.com'

    def test_clone_invalid(self):
        with patch.object(GitImporter, "__init__", return_value=None):
            c = GitImporter(None)
            c.repo_url = "git+https://github.com/ziadhany/invalid_url"  # invalid_url
            with pytest.raises(ForkError):
                c.clone()
