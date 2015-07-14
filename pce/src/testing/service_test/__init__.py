"""Unit testing for onramp_pce_service.py."""
import os
import shutil
import time
import unittest
from configobj import ConfigObj
from subprocess import CalledProcessError, check_output

class TestModtest(unittest.TestCase):

    def setUp(self):
        self.ret_dir = os.getcwd()
        os.chdir('../../')
        self.conf = ConfigObj('src/testing/testmodule/testing/modtest.ini',
                              configspec='src/configspecs/modtest.inispec')
        dummy_filepath = 'src/testing/testmodule/testing/dummy_runparams.ini'
        self.dummy_ini = ConfigObj(dummy_filepath)

        self.deploy_path = os.path.abspath(self.conf['deploy_path'])
        if os.path.isdir(self.deploy_path):
            shutil.rmtree(self.deploy_path)

        self.out_noclean_noverbose_noerror = ('deploy_check.py running...\n%s\n'
                                              'deploy_check.py passes.\nOutput '
                                              'file from job: %s/output.txt\n'
                                              % (self.deploy_path,
                                                 self.deploy_path))

        self.out_noclean_verbose_noerror = ('Running bin/onramp_deploy.py\n'
                                            'Running post_deploy_test\n'
                                            'deploy_check.py running...\n%s\n'
                                            'deploy_check.py passes.\n'
                                            'Simulating generation of onramp_runparams.ini\n'
                                            'Running bin/onramp_preprocess.py\n'
                                            'Launching job\n'
                                            'Waiting/polling job state for completion\n'
                                            'Running bin/onramp_postprocess.py\n'
                                            'No errors found.\n'
                                            'Output file from job: %s/output.txt\n'
                                            % (self.deploy_path,
                                               self.deploy_path))

        self.out_clean_noverbose_noerror = ('deploy_check.py running...\n%s\n'
                                            'deploy_check.py passes.\n'
                                            % self.deploy_path)

        self.out_clean_verbose_noerror = ('Running bin/onramp_deploy.py\n'
                                          'Running post_deploy_test\n'
                                          'deploy_check.py running...\n%s\n'
                                          'deploy_check.py passes.\n'
                                          'Simulating generation of onramp_runparams.ini\n'
                                          'Running bin/onramp_preprocess.py\n'
                                          'Launching job\n'
                                          'Waiting/polling job state for completion\n'
                                          'Running bin/onramp_postprocess.py\n'
                                          'No errors found.\n'
                                          % self.deploy_path)

    def tearDown(self):
        if os.path.isdir(self.deploy_path):
            shutil.rmtree(self.deploy_path)
        os.chdir(self.ret_dir)
        time.sleep(30)

    def modtest_test_noclean_noverbose_noerror(self):
        output = check_output(['./onramp_pce_service.py', 'modtest',
                               'src/testing/testmodule/testing/modtest.ini'])
        self.assertEqual(output, self.out_noclean_noverbose_noerror)

        # Verify onramp_runparams matches self.dummy_ini
        runparams_ini = ConfigObj(os.path.join(self.deploy_path,
                                               'onramp_runparams.ini'))
        self.assertEqual(runparams_ini, self.dummy_ini)

        # Verify deploy tree
        mod_path = 'src/testing/testmodule'
        for root, dirs, files in os.walk(mod_path):
            for name in files:
                f = os.path.join(root, name).split(mod_path)[1]
                res = os.path.isfile(self.deploy_path + f)
                self.assertTrue(res)
            for name in dirs:
                d = os.path.join(root, name).split(mod_path)[1]
                res = os.path.isdir(self.deploy_path + d)
                self.assertTrue(res)

    def modtest_test_noclean_verbose_noerror(self):
        output = check_output(['./onramp_pce_service.py', 'modtest', '-v',
                               'src/testing/testmodule/testing/modtest.ini'])

        for line in self.out_noclean_verbose_noerror.split('\n'):
            self.assertIn(line, output)

        # Verify onramp_runparams matches self.dummy_ini
        runparams_ini = ConfigObj(os.path.join(self.deploy_path,
                                               'onramp_runparams.ini'))
        self.assertEqual(runparams_ini, self.dummy_ini)

        # Verify deploy tree
        mod_path = 'src/testing/testmodule'
        for root, dirs, files in os.walk(mod_path):
            for name in files:
                f = os.path.join(root, name).split(mod_path)[1]
                res = os.path.isfile(self.deploy_path + f)
                self.assertTrue(res)
            for name in dirs:
                d = os.path.join(root, name).split(mod_path)[1]
                res = os.path.isdir(self.deploy_path + d)
                self.assertTrue(res)

    def modtest_test_clean_verbose_noerror(self):
        output = check_output(['./onramp_pce_service.py', 'modtest', '-v',
                               'src/testing/testmodule/testing/modtest-clean.ini'])

        for line in self.out_clean_verbose_noerror.split('\n'):
            self.assertIn(line, output)

        self.assertFalse(os.path.isdir(self.deploy_path))