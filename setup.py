import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="bluepy-scratch-link-shin-kawasaki",
    version="0.0.9",
    author="Shin'ichiro Kawasaki",
    author_email='kawasaki@juno.dti.ne.jp',
    description='Scratch-link for Linux with Python',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/kawasaki/bluepy-scratch-link",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3.6",
        "License :: OSI Approved :: BSD License",
        "Operating System :: POSIX :: Linux",
        ],
    python_requires='>=3.6',
    entry_points={
        'console_scripts': [
            'scratch_link = bluepy_scratch_link.scratch_link:main',
            'bluepy_helper_cap = bluepy_scratch_link.bluepy_helper_cap:setcap'
        ],
    },
)
