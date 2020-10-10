#!/bin/bash

usage() {
	echo "Usage: ${0} COMMAND"
	echo -e "COMMAND:"
	echo -e "\tbuild"
	echo -e "\tupload-testpypi FILES"
	exit 1
}

case ${1} in
	build)
		python setup.py sdist bdist_wheel
		;;
	upload-testpypi)
		shift
		python -m twine upload --repository testpypi "$@"
		;;
	*)
		usage
		;;
esac
