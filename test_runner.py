```python
"""Independent validation of TargetRunner.

Tests whether the runner can:
1. Launch the C++ target.
2. Send sequential stdin inputs.
3. Capture stdout and stderr.
4. Detect execution errors.
5. Verify SQL injection behaviour.
"""

from target_runner import TargetRunner


def main():

    print("=" * 60)
    print("       CPP SECURITY ENGINE - TARGET RUNNER TEST")
    print("=" * 60)

    # Initialize runner using config.py settings.
    runner = TargetRunner()

    # SQL injection test payload.
    payload = "1' OR '1'='1"

    print("\n[TEST] Executing Campus Utility application...")
    print("[TEST] Selecting Student Lookup (menu option 1)")
    print("[TEST] Sending SQL injection payload")

    result = runner.run(
        test_id="manual_sqli_validation",
        payload=payload
    )

    # Display execution details.
    print("\n" + "-" * 60)
    print("EXECUTION DETAILS")
    print("-" * 60)

    print("Test ID:", result.test_id)
    print("Command:", result.command)
    print("Return Code:", result.return_code)
    print("Execution Time:", round(result.duration_s, 4), "seconds")
    print("Timed Out:", result.timed_out)
    print("Error:", result.error)

    # Display stdin.
    print("\n" + "-" * 60)
    print("INPUT SENT TO C++ APPLICATION")
    print("-" * 60)

    print(result.stdin_sent)

    # Display stdout.
    print("\n" + "-" * 60)
    print("APPLICATION OUTPUT (STDOUT)")
    print("-" * 60)

    print(result.stdout)

    # Display stderr.
    print("\n" + "-" * 60)
    print("APPLICATION ERRORS (STDERR)")
    print("-" * 60)

    print(result.stderr if result.stderr else "No errors captured.")

    # Basic result validation.
    print("\n" + "-" * 60)
    print("VALIDATION")
    print("-" * 60)

    if result.error:
        print("[FAIL] Target execution failed.")

    elif result.timed_out:
        print("[FAIL] Target execution timed out.")

    elif result.return_code != 0:
        print("[WARNING] Target returned a non-zero exit code.")

    else:
        output = result.stdout.lower()

        students = ["alice", "bob", "charlie"]

        found = [
            student
            for student in students
            if student in output
        ]

        if len(found) == 3:
            print("[PASS] All three student records appeared.")
            print("[CONFIRMED] Runner reached Student Lookup.")
            print("[CONFIRMED] SQL injection behaviour reproduced.")

        elif found:
            print("[PARTIAL] Students found:", found)
            print("[CHECK] Inspect application output.")

        else:
            print("[FAIL] Expected student records were not found.")
            print("[CHECK] Verify menu sequence and target output.")

    print("\n" + "=" * 60)
    print("                 TEST COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()
