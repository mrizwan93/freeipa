#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import time
import re
from tempfile import NamedTemporaryFile
import textwrap
import pytest
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_plugins.integration import tasks
from ipatests.pytest_plugins.integration.tasks import (
    assert_error, replicas_cleanup)
from ipalib.constants import DOMAIN_LEVEL_0
from ipalib.constants import DOMAIN_LEVEL_1
from ipalib.constants import DOMAIN_SUFFIX_NAME


class ReplicaPromotionBase(IntegrationTest):

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, domain_level=cls.domain_level)

    def test_kra_install_master(self):
        result1 = tasks.install_kra(self.master,
                                    first_instance=True,
                                    raiseonerr=False)
        assert result1.returncode == 0, result1.stderr_text
        tasks.kinit_admin(self.master)
        result2 = self.master.run_command(["ipa", "vault-find"],
                                          raiseonerr=False)
        found = result2.stdout_text.find("0 vaults matched")
        assert(found > 0), result2.stdout_text


class TestReplicaPromotionLevel0(ReplicaPromotionBase):

    topology = 'star'
    num_replicas = 1
    domain_level = DOMAIN_LEVEL_0

    @replicas_cleanup
    def test_promotion_disabled(self):
        """
        Testcase:
        http://www.freeipa.org/page/V4/Replica_Promotion/Test_plan#Test_case:
        _Make_sure_the_feature_is_unavailable_under_domain_level_0
        """
        client = self.replicas[0]
        tasks.install_client(self.master, client)
        args = ['ipa-replica-install', '-U',
                '-p', self.master.config.dirman_password,
                '-w', self.master.config.admin_password,
                '--ip-address', client.ip]
        result = client.run_command(args, raiseonerr=False)
        assert_error(result,
                     'You must provide a file generated by ipa-replica-prepare'
                     ' to create a replica when the domain is at level 0', 1)

    @pytest.mark.xfail(reason="Ticket N 6274")
    @replicas_cleanup
    def test_backup_restore(self):
        """
        TestCase:
        http://www.freeipa.org/page/V4/Replica_Promotion/Test_plan#Test_case:
        _ipa-restore_after_domainlevel_raise_restores_original_domain_level
        """
        command = ["ipa", "topologysegment-find", DOMAIN_SUFFIX_NAME]
        tasks.install_replica(self.master, self.replicas[0])
        backup_file = tasks.ipa_backup(self.master)
        self.master.run_command(["ipa", "domainlevel-set", str(DOMAIN_LEVEL_1)])
        # We need to give the server time to merge 2 one-way segments into one
        time.sleep(10)
        result = self.master.run_command(command)
        found1 = result.stdout_text.rfind("1 segment matched")
        assert(found1 > 0), result.stdout_text
        tasks.ipa_restore(self.master, backup_file)
        result2 = self.master.run_command(command, raiseonerr=False)
        found2 = result2.stdout_text.rfind("0 segments matched")
        assert(found2 > 0), result2.stdout_text


@pytest.mark.xfail(reason="Ticket N 6274")
class TestKRAInstall(IntegrationTest):
    """
    TestCase: http://www.freeipa.org/page/V4/Replica_Promotion/Test_plan
    #Test_case:_ipa-kra-install_with_replica_file_works_only_on_domain_level_0
    """
    topology = 'star'
    domain_level = DOMAIN_LEVEL_0
    num_replicas = 2

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, domain_level=cls.domain_level)

    def test_kra_install_without_replica_file(self):
        master = self.master
        replica1 = self.replicas[0]
        replica2 = self.replicas[1]
        tasks.install_kra(master, first_instance=True)
        tasks.install_replica(master, replica1)
        result1 = tasks.install_kra(replica1,
                                    domain_level=DOMAIN_LEVEL_1,
                                    raiseonerr=False)
        assert_error(result1, "A replica file is required", 1)
        tasks.install_kra(replica1,
                          domain_level=DOMAIN_LEVEL_0,
                          raiseonerr=True)
        # Now prepare the replica file, copy it to the client and raise
        # domain level on master to test the reverse situation
        tasks.replica_prepare(master, replica2)
        master.run_command(["ipa", "domainlevel-set", str(DOMAIN_LEVEL_1)])
        tasks.install_replica(master, replica2)
        result2 = tasks.install_kra(replica2,
                                    domain_level=DOMAIN_LEVEL_0,
                                    raiseonerr=False)
        assert_error(result2, "No replica file is required", 1)
        tasks.install_kra(replica2)


@pytest.mark.xfail(reason="Ticket N 6274")
class TestCAInstall(IntegrationTest):
    topology = 'star'
    domain_level = DOMAIN_LEVEL_0
    num_replicas = 2

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, domain_level=cls.domain_level)

    def test_ca_install_without_replica_file(self):
        """
        TestCase:
        http://www.freeipa.org/page/V4/Replica_Promotion/Test_plan#Test_case:
        _ipa-ca-install_with_replica_file_works_only_on_domain_level_0
        """
        master = self.master
        replica1 = self.replicas[0]
        replica2 = self.replicas[1]
        for replica in self.replicas:
            tasks.install_replica(master, replica, setup_ca=False,
                                  setup_dns=True)
        result1 = tasks.install_ca(replica1,
                                   domain_level=DOMAIN_LEVEL_1,
                                   raiseonerr=False)
        assert_error(result1, "If you wish to replicate CA to this host,"
                              " please re-run 'ipa-ca-install'\nwith a"
                              " replica file generated on an existing CA"
                              " master as argument.", 1)

        tasks.install_ca(replica1, domain_level=DOMAIN_LEVEL_0)
        # Now prepare the replica file, copy it to the client and raise
        # domain level on master to test the reverse situation
        master.run_command(["ipa", "domainlevel-set", str(DOMAIN_LEVEL_1)])
        result2 = tasks.install_ca(replica2,
                                   domain_level=DOMAIN_LEVEL_0,
                                   raiseonerr=False)
        assert_error(result2, 'Too many parameters provided.'
                              ' No replica file is required', 1)
        tasks.install_ca(replica2, domain_level=DOMAIN_LEVEL_1)


class TestReplicaPromotionLevel1(ReplicaPromotionBase):
    """
    TestCase: http://www.freeipa.org/page/V4/Replica_Promotion/Test_plan#
    Test_case:_Make_sure_the_old_workflow_is_disabled_at_domain_level_1
    """

    topology = 'star'
    num_replicas = 1
    domain_level = DOMAIN_LEVEL_1

    @replicas_cleanup
    def test_replica_prepare_disabled(self):
        replica = self.replicas[0]
        args = ['ipa-replica-prepare',
                '-p', self.master.config.dirman_password,
                '--ip-address', replica.ip,
                replica.hostname]
        result = self.master.run_command(args, raiseonerr=False)
        assert_error(result, "Replica creation using 'ipa-replica-prepare'"
                             " to generate replica file\n"
                             "is supported only in 0-level IPA domain", 1)

    @replicas_cleanup
    def test_one_command_installation(self):
        """
        TestCase:
        http://www.freeipa.org/page/V4/Replica_Promotion/Test_plan
        #Test_case:_Replica_can_be_installed_using_one_command
        """
        self.replicas[0].run_command(['ipa-replica-install', '-w',
                                     self.master.config.admin_password,
                                     '-n', self.master.domain.name,
                                     '-r', self.master.domain.realm,
                                     '--server', self.master.hostname,
                                     '-U'])


@pytest.mark.xfail(reason="Ticket N 6274")
class TestReplicaManageCommands(IntegrationTest):
    topology = "star"
    num_replicas = 2
    domain_level = DOMAIN_LEVEL_0

    def test_replica_manage_commands(self):
        """
        TestCase: http://www.freeipa.org/page/V4/Replica_Promotion/Test_plan
        #Test_case:_ipa-replica-manage_connect_is_deprecated_in_domain_level_1
        """
        master = self.master
        replica1 = self.replicas[0]
        replica2 = self.replicas[1]

        result1 = master.run_command(["ipa-replica-manage",
                                      "connect",
                                      replica1.hostname,
                                      replica2.hostname],
                                     raiseonerr=False)
        assert result1.returncode == 0, result1.stderr_text
        result2 = master.run_command(["ipa-replica-manage",
                                      "disconnect",
                                      replica1.hostname,
                                      replica2.hostname],
                                     raiseonerr=False)
        assert result2.returncode == 0, result2.stderr_text
        master.run_command(["ipa", "domainlevel-set", str(DOMAIN_LEVEL_1)])
        result3 = master.run_command(["ipa-replica-manage",
                                      "connect",
                                      replica1.hostname,
                                      replica2.hostname],
                                     raiseonerr=False)
        assert_error(result3, 'Creation of IPA replication agreement is'
                              ' deprecated with managed IPA replication'
                              ' topology. Please use `ipa topologysegment-*`'
                              ' commands to manage the topology', 1)
        segment = tasks.create_segment(master, replica1, replica2)
        result4 = master.run_command(["ipa-replica-manage",
                                      "disconnect",
                                      replica1.hostname,
                                      replica2.hostname],
                                     raiseonerr=False)
        assert_error(result4, 'Removal of IPA replication agreement is'
                              ' deprecated with managed IPA replication'
                              ' topology. Please use `ipa topologysegment-*`'
                              ' commands to manage the topology', 1)

        # http://www.freeipa.org/page/V4/Replica_Promotion/Test_plan
        #Test_case:_ipa-csreplica-manage_connect_is_deprecated
        #_in_domain_level_1

        result5 = master.run_command(['ipa-csreplica-manage', 'del',
                                      replica1.hostname,
                                      '-p', master.config.dirman_password],
                                     raiseonerr=False)
        assert_error(result5, "Removal of IPA CS replication agreement"
                              " and replication data is deprecated with"
                              " managed IPA replication topology", 1)

        tasks.destroy_segment(master, segment[0]['name'])
        result6 = master.run_command(["ipa-csreplica-manage",
                                      "connect",
                                      replica1.hostname,
                                      replica2.hostname,
                                      '-p', master.config.dirman_password],
                                     raiseonerr=False)
        assert_error(result6, "Creation of IPA CS replication agreement is"
                              " deprecated with managed IPA replication"
                              " topology", 1)
        tasks.create_segment(master, replica1, replica2)
        result7 = master.run_command(["ipa-csreplica-manage",
                                      "disconnect",
                                      replica1.hostname,
                                      replica2.hostname,
                                      '-p', master.config.dirman_password],
                                     raiseonerr=False)
        assert_error(result7, "Removal of IPA CS replication agreement is"
                              " deprecated with managed IPA"
                              " replication topology", 1)


class TestUnprivilegedUserPermissions(IntegrationTest):
    """
    TestCase:
    http://www.freeipa.org/page/V4/Replica_Promotion/Test_plan
    #Test_case:_Unprivileged_users_are_not_allowed_to_enroll
    _and_promote_clients
    """
    num_replicas = 1
    domain_level = DOMAIN_LEVEL_1

    @classmethod
    def install(cls, mh):
        cls.username = 'testuser'
        tasks.install_master(cls.master, domain_level=cls.domain_level)
        password = cls.master.config.dirman_password
        cls.new_password = '$ome0therPaaS'
        adduser_stdin_text = "%s\n%s\n" % (cls.master.config.admin_password,
                                           cls.master.config.admin_password)
        user_kinit_stdin_text = "%s\n%s\n%s\n" % (password, cls.new_password,
                                                  cls.new_password)
        tasks.kinit_admin(cls.master)
        cls.master.run_command(['ipa', 'user-add', cls.username, '--password',
                                '--first', 'John', '--last', 'Donn'],
                               stdin_text=adduser_stdin_text)
        # Now we need to change the password for the user
        cls.master.run_command(['kinit', cls.username],
                               stdin_text=user_kinit_stdin_text)
        # And again kinit admin
        tasks.kinit_admin(cls.master)

    def test_client_enrollment_by_unprivileged_user(self):
        replica = self.replicas[0]
        result1 = replica.run_command(['ipa-client-install',
                                       '-p', self.username,
                                       '-w', self.new_password,
                                       '--domain', replica.domain.name,
                                       '--realm', replica.domain.realm, '-U',
                                       '--server', self.master.hostname],
                                      raiseonerr=False)
        assert_error(result1, "No permission to join this host", 1)

    def test_replica_promotion_by_unprivileged_user(self):
        replica = self.replicas[0]
        tasks.install_client(self.master, replica)
        result2 = replica.run_command(['ipa-replica-install',
                                       '-P', self.username,
                                       '-p', self.new_password,
                                       '-n', self.master.domain.name,
                                       '-r', self.master.domain.realm],
                                      raiseonerr=False)
        assert_error(result2,
                     "Insufficient privileges to promote the server", 1)

    def test_replica_promotion_after_adding_to_admin_group(self):
        self.master.run_command(['ipa', 'group-add-member', 'admins',
                                 '--users=%s' % self.username])

        self.replicas[0].run_command(['ipa-replica-install',
                                      '-P', self.username,
                                      '-p', self.new_password,
                                      '-n', self.master.domain.name,
                                      '-r', self.master.domain.realm,
                                      '-U'])


class TestProhibitReplicaUninstallation(IntegrationTest):
    topology = 'line'
    num_replicas = 2
    domain_level = DOMAIN_LEVEL_1

    def test_replica_uninstallation_prohibited(self):
        """
        http://www.freeipa.org/page/V4/Replica_Promotion/Test_plan
        #Test_case:_Prohibit_ipa_server_uninstallation_from_disconnecting
        _topology_segment
        """
        result = self.replicas[0].run_command(['ipa-server-install',
                                               '--uninstall', '-U'],
                                              raiseonerr=False)
        assert_error(result, "Removal of '%s' leads to disconnected"
                             " topology" % self.replicas[0].hostname, 1)
        self.replicas[0].run_command(['ipa-server-install', '--uninstall',
                                      '-U', '--ignore-topology-disconnect'])


@pytest.mark.xfail(reason="Ticket N 6274")
class TestOldReplicaWorksAfterDomainUpgrade(IntegrationTest):
    topology = 'star'
    num_replicas = 1
    domain_level = DOMAIN_LEVEL_0
    username = 'testuser'

    def test_replica_after_domain_upgrade(self):
        tasks.kinit_admin(self.master)
        tasks.kinit_admin(self.replicas[0])
        self.master.run_command(['ipa', 'user-add', self.username,
                                 '--first', 'test',
                                 '--last', 'user'])
        tasks.wait_for_replication(self.replicas[0].ldap_connect())
        self.master.run_command(['ipa', 'domainlevel-set',
                                 str(DOMAIN_LEVEL_1)])
        result = self.replicas[0].run_command(['ipa', 'user-show',
                                               self.username])
        assert("User login: %s" % self.username in result.stdout_text), (
                "A testuser was not found on replica after domain upgrade")
        self.replicas[0].run_command(['ipa', 'user-del', self.username])
        tasks.wait_for_replication(self.master.ldap_connect())
        result1 = self.master.run_command(['ipa', 'user-show', self.username],
                                          raiseonerr=False)
        assert_error(result1, "%s: user not found" % self.username, 2)


class TestWrongClientDomain(IntegrationTest):
    topology = "star"
    num_replicas = 1
    domain_name = 'exxample.test'
    domain_level = DOMAIN_LEVEL_1

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, domain_level=cls.domain_level)

    def teardown_method(self, method):
        self.replicas[0].run_command(['ipa-client-install',
                                     '--uninstall', '-U'],
                                    raiseonerr=False)
        tasks.kinit_admin(self.master)
        self.master.run_command(['ipa', 'host-del',
                                 self.replicas[0].hostname],
                                raiseonerr=False)

    def test_wrong_client_domain(self):
        client = self.replicas[0]
        client.run_command(['ipa-client-install', '-U',
                            '--domain', self.domain_name,
                            '--realm', self.master.domain.realm,
                            '-p', 'admin',
                            '-w', self.master.config.admin_password,
                            '--server', self.master.hostname,
                            '--force-join'])
        result = client.run_command(['ipa-replica-install', '-U', '-w',
                                     self.master.config.dirman_password],
                                    raiseonerr=False)
        assert_error(result,
                     "Cannot promote this client to a replica. Local domain "
                     "'%s' does not match IPA domain "
                     "'%s'" % (self.domain_name, self.master.domain.name))

    def test_upcase_client_domain(self):
        client = self.replicas[0]
        result = client.run_command(['ipa-client-install', '-U', '--domain',
                                     self.master.domain.name.upper(), '-w',
                                     self.master.config.admin_password,
                                     '-p', 'admin',
                                     '--server', self.master.hostname,
                                     '--force-join'], raiseonerr=False)
        assert(result.returncode == 0), (
            'Failed to setup client with the upcase domain name')
        result1 = client.run_command(['ipa-replica-install', '-U', '-w',
                                      self.master.config.dirman_password],
                                     raiseonerr=False)
        assert(result1.returncode == 0), (
            'Failed to promote the client installed with the upcase domain name')


class TestRenewalMaster(IntegrationTest):

    topology = 'star'
    num_replicas = 1

    @classmethod
    def uninstall(cls, mh):
        super(TestRenewalMaster, cls).uninstall(mh)

    def assertCARenewalMaster(self, host, expected):
        """ Ensure there is only one CA renewal master set """
        result = host.run_command(["ipa", "config-show"]).stdout_text
        matches = list(re.finditer('IPA CA renewal master: (.*)', result))
        assert len(matches), 1
        assert matches[0].group(1) == expected

    def test_replica_not_marked_as_renewal_master(self):
        """
        https://fedorahosted.org/freeipa/ticket/5902
        """
        master = self.master
        replica = self.replicas[0]
        result = master.run_command(["ipa", "config-show"]).stdout_text
        assert("IPA CA renewal master: %s" % master.hostname in result), (
            "Master hostname not found among CA renewal masters"
        )
        assert("IPA CA renewal master: %s" % replica.hostname not in result), (
            "Replica hostname found among CA renewal masters"
        )

    def test_manual_renewal_master_transfer(self):
        replica = self.replicas[0]
        replica.run_command(['ipa', 'config-mod',
                             '--ca-renewal-master-server', replica.hostname])
        result = self.master.run_command(["ipa", "config-show"]).stdout_text
        assert("IPA CA renewal master: %s" % replica.hostname in result), (
            "Replica hostname not found among CA renewal masters"
        )
        # additional check e.g. to see if there is only one renewal master
        self.assertCARenewalMaster(replica, replica.hostname)

    def test_renewal_master_with_csreplica_manage(self):

        master = self.master
        replica = self.replicas[0]

        self.assertCARenewalMaster(master, replica.hostname)
        self.assertCARenewalMaster(replica, replica.hostname)

        master.run_command(['ipa-csreplica-manage', 'set-renewal-master',
                            '-p', master.config.dirman_password])
        result = master.run_command(["ipa", "config-show"]).stdout_text

        assert("IPA CA renewal master: %s" % master.hostname in result), (
            "Master hostname not found among CA renewal masters"
        )

        # lets give replication some time
        time.sleep(60)

        self.assertCARenewalMaster(master, master.hostname)
        self.assertCARenewalMaster(replica, master.hostname)

        replica.run_command(['ipa-csreplica-manage', 'set-renewal-master',
                             '-p', replica.config.dirman_password])
        result = replica.run_command(["ipa", "config-show"]).stdout_text

        assert("IPA CA renewal master: %s" % replica.hostname in result), (
            "Replica hostname not found among CA renewal masters"
        )

        self.assertCARenewalMaster(master, replica.hostname)
        self.assertCARenewalMaster(replica, replica.hostname)

    def test_automatic_renewal_master_transfer_ondelete(self):
        # Test that after replica uninstallation, master overtakes the cert
        # renewal master role from replica (which was previously set there)
        tasks.uninstall_master(self.replicas[0])
        result = self.master.run_command(['ipa', 'config-show']).stdout_text
        assert("IPA CA renewal master: %s" % self.master.hostname in result), (
            "Master hostname not found among CA renewal masters"
        )


class TestReplicaInstallWithExistingEntry(IntegrationTest):
    """replica install might fail because of existing entry for replica like
    `cn=ipa-http-delegation,cn=s4u2proxy,cn=etc,$SUFFIX` etc. The situation
    may arise due to incorrect uninstall of replica.

    https://pagure.io/freeipa/issue/7174"""

    num_replicas = 1

    def test_replica_install_with_existing_entry(self):
        master = self.master
        tasks.install_master(master)
        replica = self.replicas[0]
        tf = NamedTemporaryFile()
        ldif_file = tf.name
        base_dn = "dc=%s" % (",dc=".join(replica.domain.name.split(".")))
        # adding entry for replica on master so that master will have it before
        # replica installtion begins and creates a situation for pagure-7174
        entry_ldif = textwrap.dedent("""
            dn: cn=ipa-http-delegation,cn=s4u2proxy,cn=etc,{base_dn}
            changetype: modify
            add: memberPrincipal
            memberPrincipal: HTTP/{hostname}@{realm}

            dn: cn=ipa-ldap-delegation-targets,cn=s4u2proxy,cn=etc,{base_dn}
            changetype: modify
            add: memberPrincipal
            memberPrincipal: ldap/{hostname}@{realm}""").format(
            base_dn=base_dn, hostname=replica.hostname,
            realm=replica.domain.name.upper())
        master.put_file_contents(ldif_file, entry_ldif)
        arg = ['ldapmodify',
               '-h', master.hostname,
               '-p', '389', '-D',
               str(master.config.dirman_dn),   # pylint: disable=no-member
               '-w', master.config.dirman_password,
               '-f', ldif_file]
        master.run_command(arg)

        tasks.install_replica(master, replica)


class TestRecomendedReplicationAgreement(IntegrationTest):
    """Maximum recomended number of agreements per replica is 4.
    This test checks if number of agreement exceeds the recomendation,
    warnning should be given to the user

    related ticket : https://pagure.io/freeipa/issue/6533"""

    num_replicas = 5

    def test_recomended_replication_agreement(self):
        tasks.install_topo('star', self.master, self.replicas,
                           [], setup_replica_cas=False)
        arg = ['ipa', 'topologysuffix-verify', 'domain']
        cmd = self.master.run_command(arg)
        expected_str1 = ("Recommended maximum number of "
                         "agreements per replica exceeded")
        expected_str2 = "Maximum number of agreements per replica: 4"
        assert (expected_str1 in cmd.stdout_text) and (
               expected_str2 in cmd.stdout_text)
