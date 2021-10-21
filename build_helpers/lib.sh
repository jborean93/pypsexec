#!/bin/bash


lib::setup::windows_requirements() {
    echo "Installing Windows pre-requisites"

    export PYPSEXEC_SERVER=localhost
    export PYPSEXEC_ALT_USERNAME=PSExecTest
    export PYPSEXEC_ALT_PASSWORD=Password123

    powershell.exe -NoLogo -NoProfile \
        -File ./build_helpers/win-setup.ps1 \
        -UserName "${PYPSEXEC_ALT_USERNAME}" \
        -Password "${PYPSEXEC_ALT_PASSWORD}" \
        -InformationAction Continue
}

lib::setup::system_requirements() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Installing System Requirements"
    fi

    if [ -f /etc/debian_version ]; then
        echo "No requirements required for Linux"

    elif [ "$(expr substr $(uname -s) 1 5)" == "MINGW" ]; then
        lib::setup::windows_requirements

    else
        echo "Distro not found!"
        false
    fi

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

lib::setup::python_requirements() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Installing Python Requirements"
    fi

    echo "Upgrading baseline packages"
    python -m pip install --upgrade pip setuptools wheel

    echo "Installing pypsexec"
    python -m pip install .

    echo "Install test requirements"
    python -m pip install -r requirements-test.txt

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

lib::sanity::run() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Running Sanity Checks"
    fi

    python -m pycodestyle \
        pypsexec \
        --verbose \
        --show-source \
        --statistics

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}

lib::tests::run() {
    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::group::Running Tests"
    fi

    python -m pytest \
        --verbose \
        --junitxml junit/test-results.xml \
        --cov pypsexec \
        --cov-report xml \
        --cov-report term-missing

    if [ x"${GITHUB_ACTIONS}" = "xtrue" ]; then
        echo "::endgroup::"
    fi
}
