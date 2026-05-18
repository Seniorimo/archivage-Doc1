package security

default allow := false

strict_mode if {
    input.settings.enforce_gate == true
}

scans_ok if {
    input.scan_status.gitleaks == "ok"
    input.scan_status.trivy == "ok"
    input.scan_status.zap == "ok"
}

sonar_ok if {
    input.sonarqube.quality_gate != "ERROR"
}

thresholds_ok if {
    count(input.gitleaks) == 0
    input.trivy.critical == 0
    input.zap.high == 0
    sonar_ok
}

allow if {
    scans_ok
    not strict_mode
}

allow if {
    scans_ok
    strict_mode
    thresholds_ok
}
