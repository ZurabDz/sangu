import random


def simulate_zkp_malicious(trials=20):
    """
    Simulates the Ali Baba Cave ZKP for a MALICIOUS prover (Alice)
    who does NOT know the secret password and is guessing.
    Calculates the success probability over a number of trials.
    """
    success_count = 0
    print(f"--- Simulating Malicious Prover ({trials} trials) ---")
    for i in range(trials):
        # 1. Commitment: Malicious Alice randomly picks a path
        path_entered = random.choice(['A', 'B'])

        # 2. Challenge: Bob randomly challenges Alice to exit from a path
        challenge = random.choice(['A', 'B'])

        # 3. Response: Simulate Alice's attempt
        knows_password = False # <<< KEY CHANGE: Set to False for malicious prover

        if knows_password:
            # This block would run for an HONEST prover (always succeeds)
            # We keep it for structure, but it won't execute now.
            success = True
        else:
            # MALICIOUS prover logic:
            # Success only if Bob's challenge matches the path Alice initially chose.
            # She cannot switch paths without the password.
            success = (path_entered == challenge)

        if success:
            success_count += 1

    # Calculate and print the success probability
    success_probability = success_count / trials
    print(f"Malicious prover succeeded in {success_count} out of {trials} trials.")
    print(f"Success Probability for Malicious Prover: {success_probability:.2f}")
    print("----------------------------------------------------")
    print("Note: Theoretically, a malicious prover has a 1/2 chance of succeeding in a single trial.")
    print("Repeating the trial N times, the chance of fooling the verifier N times is (1/2)^N.")

# Run the simulation for the malicious prover
simulate_zkp_malicious(trials=20)

# Optional: Run with more trials for a statistically better estimate
# simulate_zkp_malicious(trials=1000)