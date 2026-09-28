from setuptools import setup
import setup_translate

pkg = 'SystemPlugins.RemoteSupport'
setup(name='enigma2-plugin-systemplugins-remotesupport',
       version='1.0',
       description='Remote support for a receiver through a shared terminal in the web browser (sshx)',
       package_dir={pkg: 'RemoteSupport'},
       packages=[pkg],
       package_data={pkg: ['*.png', 'locale/*/LC_MESSAGES/*.mo']},
       data_files=[('/usr/bin', ['bin/remotesupport'])],
       cmdclass=setup_translate.cmdclass,
      )
