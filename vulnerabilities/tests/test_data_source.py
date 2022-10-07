#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
from unittest import TestCase
from unittest.mock import patch

import pytest
from fetchcode.vcs import VCSResponse

from vulnerabilities.importer import ForkError
from vulnerabilities.importer import GitImporter

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/")


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
