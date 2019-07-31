import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="OSfooler-ng",
    version="v1.00b",
    author='Jaime Sanchez (@segofensiva)',
    author_email='jsanchez@seguridadofensiva.com',
    description='OSfooler-ng prevents remote OS active/passive fingerprinting by tools like nmap or p0f',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/segofensiva/OSfooler-ng',
    include_package_data=True,
    entry_points = {
        'console_scripts': ['osfooler-ng=osfooler_ng.osfooler_ng:main'],
    },
    packages=setuptools.find_packages(),
    install_requires=open('requirements.txt').read().splitlines(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Operating System :: POSIX :: Linux",
        "Topic :: System :: Networking",
        "Programming Language :: Python",
        "Topic :: Security",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)"
],
)
