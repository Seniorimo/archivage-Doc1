package security

default allow := false

default thresholds_ok := false

# Pass only when all blocking vulnerability thresholds are zero.
thresholds_ok if {
    input.trivy.critical == 0
    input.trivy.high == 0
    input.zap.high == 0
}

# Demo mode: skip enforcement when the gate is not required.
allow if {
    input.enforce_gate == false
}

# Strict mode: allow only when vulnerability thresholds are satisfied.
allow if {
    input.enforce_gate == true
    thresholds_ok
}
