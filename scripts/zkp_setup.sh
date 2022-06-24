#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "$0" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR=$( dirname "$SCRIPT_DIR" )
CONTRACTS_DIR=${ROOT_DIR}/contracts
INPUTS_DIR=${ROOT_DIR}/private # for tests

# circuits with max 2^POWERS_OF_TAU constraints
POWERS_OF_TAU=20 # TODO: load from .env
ARTIFACTS_DIR=build
TAU_DIR=${ARTIFACTS_DIR}/ptau

function init() {
	mkdir -p ${TAU_DIR}

	# List of current supported circuits
	circuit_source=( issue approve12 auth12 score12 )
	for circuit_file in "${circuit_source[@]}"; do
		if [ ! -d "${ARTIFACTS_DIR}/${circuit_file}" ]; then
			mkdir -p ${ARTIFACTS_DIR}/${circuit_file}
		fi
		if [ ! -d "${INPUTS_DIR}/${circuit_file}" ]; then
			mkdir -p ${INPUTS_DIR}/${circuit_file}
		fi
	done
}

function fatal() {
	echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
	exit 1
}

function check_args() {
	[[ "$#" -ne 2 ]] && fatal "Missing arguments: ${1}"
}

# https://docs.circom.io/getting-started/proving-circuits/#powers-of-tau
# Generates a setup with only ONE trusted entity
# NOTE: phase 1 can be reused in other phase 2 plonk circuits
function phase1() {
	# Phase1: Setup ceremony
	# output: ptau${POWERS_OF_TAU}_0000.ptau (powers of tau ceremony initial parameters)
  snarkjs powersoftau new bn128 ${POWERS_OF_TAU} ${TAU_DIR}/pot${POWERS_OF_TAU}_0000.ptau -v
  snarkjs powersoftau contribute ${TAU_DIR}/pot${POWERS_OF_TAU}_0000.ptau ${TAU_DIR}/pot${POWERS_OF_TAU}_0001.ptau --name="1st contribution" -v -e="$(head -n 4096 /dev/urandom | openssl sha256)"

  # Verify Phase1:
  snarkjs powersoftau verify ${TAU_DIR}/pot${POWERS_OF_TAU}_0001.ptau

  # Apply random beacon to finalised this phase of the setup.
  # For more information about random beacons see here: https://eprint.iacr.org/2017/1050.pdf
  # From: https://github.com/iden3/snarkjs/blob/master/README.md#6-apply-a-random-beacon
  # In this example the beacon is essentially a delayed hash function evaluated on 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
  # (in practice this value will be some form of high entropy and publicly available data of your choice)
  snarkjs powersoftau beacon ${TAU_DIR}/pot${POWERS_OF_TAU}_0001.ptau ${TAU_DIR}/pot${POWERS_OF_TAU}_beacon.ptau 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="Final Beacon"

  preparePhase2
}

# Prepare Phase2: Circuit specific ceremony and proving key generation
# output: pot${POWERS_OF_TAU}_final.ptau (after all phase1 contritutions, one in this case)
function preparePhase2() {
  snarkjs powersoftau prepare phase2 ${TAU_DIR}/pot${POWERS_OF_TAU}_beacon.ptau ${TAU_DIR}/pot${POWERS_OF_TAU}.ptau -v

  # Verify the final ptau file
  snarkjs powersoftau verify ${TAU_DIR}/pot${POWERS_OF_TAU}.ptau
}

# https://github.com/iden3/snarkjs#7-prepare-phase-2
function downloadTAU() {
  if [ ! -f ${TAU_DIR}/pot${POWERS_OF_TAU}.ptau ]; then
    echo "Downloading powers of tau file"
    curl -L https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_$POWERS_OF_TAU.ptau --create-dirs -o ${TAU_DIR}/pot${POWERS_OF_TAU}.ptau
  fi
}

# https://docs.circom.io/getting-started/proving-circuits/#powers-of-tau
# Generates a setup with only ONE trusted entity
# output: ${circuit}.zkey file that will contain the proving and verification keys together with all phase 2 contributions
function phase2() {
	check_args $1 "circuit not informed or found"
	circuit=$1

	CIRCUIT_DIR=${ARTIFACTS_DIR}/${circuit}

	snarkjs plonk setup ${CIRCUIT_DIR}/${circuit}.r1cs ${TAU_DIR}/pot${POWERS_OF_TAU}.ptau ${CIRCUIT_DIR}/${circuit}.zkey -v
}

# Compile the circuit
# output: circuit.sym, circuit.wasm and circuit.r1cs
function compile_circuit() {
	check_args $1 "circuit name not informed"
	circuit=$1

	CIRCUIT_DIR=${ARTIFACTS_DIR}/${circuit}

	# using circom 2.0
	# TODO: check if circom is installed
	circom circuits/${circuit}.circom --r1cs --wasm --sym -o ${CIRCUIT_DIR}
	if [ -d "${CIRCUIT_DIR}/${circuit}_js" ]; then
		mv ${CIRCUIT_DIR}/${circuit}_js/* ${CIRCUIT_DIR}
		rm -rf ${CIRCUIT_DIR}/${circuit}_js
	fi
}

# Exports verification key
# output: ${CIRCUIT_DIR}/verification_key.json
function export_verification_key() {
	check_args $1 "circuit name not informed"
	circuit=$1

	CIRCUIT_DIR=${ARTIFACTS_DIR}/${circuit}

	snarkjs zkey export verificationkey ${CIRCUIT_DIR}/${circuit}.zkey ${CIRCUIT_DIR}/verification_key.json
}

# Generates the Verifier smart contract
# output: ${CONTRACTS_DIR}/${capitalCircuitName}Verifier.sol
function gen_verifier_contract() {
	check_args $1 "circuit name not informed"
	circuit=$1

	CIRCUIT_DIR=${ARTIFACTS_DIR}/${circuit}

	local capitalCircuitName=$(echo "${circuit}" | sed 's/^[a-z]/\U&/')

	snarkjs zkey export solidityverifier ${CIRCUIT_DIR}/${circuit}.zkey ${CONTRACTS_DIR}/${capitalCircuitName}Verifier.sol -v

	# Update the solidity version and contract name
	# TODO: get solidity version from config
	sed -i "s/>=0.7.0 <0.9.0;/^0.8.0;/g" ${CONTRACTS_DIR}/${capitalCircuitName}Verifier.sol
	sed -i "s/contract PlonkVerifier/contract ${capitalCircuitName}Verifier/g" ${CONTRACTS_DIR}/${capitalCircuitName}Verifier.sol
}

# Generates witness by running the circuit over the inputs
# output: witness.wtns (private witness binary)
function gen_witness() {
	check_args $1 "circuit name not informed"
	circuit=$1

	CIRCUIT_DIR=${ARTIFACTS_DIR}/${circuit}
	INPUTS=${INPUTS_DIR}/${circuit}

	# snarkjs wtns calculate ${CIRCUIT_DIR}/${circuit}.wasm ${INPUTS}/inputs.json ${INPUTS}/witness.wtns
	node ${CIRCUIT_DIR}/generate_witness.js ${CIRCUIT_DIR}/${circuit}.wasm ${INPUTS}/inputs.json ${INPUTS}/witness.wtns

	# export witness
	# output: witness.json
	snarkjs wtns export json ${INPUTS}/witness.wtns ${INPUTS}/witness.json -v
}

# generate the proof using the proving zkey and witness
# output: proof.json and public.json
function gen_proof() {
	check_args $1 "circuit name not informed"
	circuit=$1

	CIRCUIT_DIR=${ARTIFACTS_DIR}/${circuit}
	INPUTS=${INPUTS_DIR}/${circuit}

	snarkjs plonk prove ${CIRCUIT_DIR}/${circuit}.zkey ${INPUTS}/witness.wtns ${INPUTS}/proof.json ${INPUTS}/public.json -v
}

# Generates the proof using the proving zkey and private inputs
# output: proof.json and public.json
function gen_fullproof() {
	check_args $1 "circuit name not informed"
	circuit=$1

	CIRCUIT_DIR=${ARTIFACTS_DIR}/${circuit}
	INPUTS=${INPUTS_DIR}/${circuit}

	snarkjs plonk fullprove ${INPUTS}/inputs.json ${CIRCUIT_DIR}/${circuit}.wasm ${CIRCUIT_DIR}/${circuit}.zkey ${INPUTS}/proof.json ${INPUTS}/public.json -v
}

function gen_calldata() {
	check_args $1 "circuit name not informed"
	circuit=$1
	INPUTS=${INPUTS_DIR}/${circuit}

	snarkjs generatecall -pub ${INPUTS}/public.json -proof ${INPUTS}/proof.json | tee ${INPUTS}/parameters.txt

	# or
	# output the contract's call parameters (to be passed to the verify function)
	# snarkjs zkey export soliditycalldata ${INPUTS}/public.json ${INPUTS}/proof.json | tee ${INPUTS}/parameters2.txt
}

function verify() {
	check_args $1 "circuit name not informed"
	circuit=$1

	CIRCUIT_DIR=${ARTIFACTS_DIR}/${circuit}
	INPUTS=${INPUTS_DIR}/${circuit}

	snarkjs plonk verify ${CIRCUIT_DIR}/verification_key.json ${INPUTS}/public.json ${INPUTS}/proof.json
}

usage() {
	echo "usage: ${0} [option]"
	echo 'options:'
	echo '    -download-tau  Download powers of tau'
	echo '    -phase1  Run ZKP Setup Phase1 and prepare to Phase2'
	echo '    -phase2  Run ZKP Setup Phase2'
	echo '    -compile  Compile circuits'
	echo '    -export-vkey  Export verification key json'
	echo '    -gen-vcontract  Generate verifier smart contract'
	echo '    -gen-witness  Generate witness'
	echo '    -gen-proof  Generate proof using witness'
	echo '    -gen-fullproof  Generate proof using only inputs (in-memory witness)'
	echo '    -gen-calldata  Generate calldata'
	echo '    -verify  Verify proof'
	echo
}

init
option="${1}"
case ${option} in
	-download-tau) downloadTAU;;
	-phase1) phase1;;
	-phase2) phase2 "${@:2}";;
	-compile) compile_circuit "${@:2}";;
	-export-vkey) export_verification_key "${@:2}";;
	-gen-vcontract) gen_verifier_contract "${@:2}";;
	-gen-witness) gen_witness "${@:2}";;
	-gen-proof) gen_proof "${@:2}";;
	-gen-fullproof) gen_fullproof "${@:2}";;
	-gen-calldata) gen_calldata "${@:2}";;
	-verify) verify "${@:2}";;
	*) usage; exit 1;;
esac