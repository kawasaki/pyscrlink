#!/bin/bash

usage() {
	echo "Usage: ${0} COMMAND"
	echo -e "COMMAND:"
	echo -e "\tbuild"
	echo -e "\tupload FILES"
	echo -e "\tupload-testpypi FILES"
	echo -e "examples:"
	echo -e "\t${0} build"
	echo -e "\t${0} upload dist/*0.2.6*"
	exit 1
}

case ${1} in
	build)
		python -m build
		;;
	upload)
		shift
		python -m twine upload "$@"
		;;
	upload-testpypi)
		shift
		python -m twine upload --repository testpypi "$@"
		;;
	*)
		usage
		;;
esac
