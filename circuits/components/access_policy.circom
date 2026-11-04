 pragma circom 2.2.3;

template FileShareAccess() {
    signal input role;
    signal input clearance;
    signal input deviceCompliant;
    signal input employeeActive;

    deviceCompliant === 1;
    employeeActive === 1;
    (role - 2) * (role - 3) === 0;
    (clearance - 2) * (clearance - 3) === 0;
}
