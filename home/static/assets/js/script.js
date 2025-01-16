function addFields(val) {
    let value = val.value;
    console.log(value);
    let container = document.getElementById("dynamic_input_field_container"); // Get the element where the inputs will be added to

    // Remove every child it had before
    while (container.hasChildNodes()) {
        container.removeChild(container.lastChild);
    }

    if (value === "Website") {
        let elChild = document.createElement("div");
        elChild.innerHTML = `
                            <div>
                                <div class="form-floating mb-4">
                                    <input type="text" class="form-control" id="website_name" name="website_name"
                                           placeholder="website name">
                                    <label for="website_name">Website name</label>
                                </div>
                                <div class="form-floating mb-4">
                                    <input type="text" class="form-control" id="website_url" name="website_url"
                                           placeholder="url">
                                    <label for="website_url">Website URL</label>
                                </div>
                            </div>`;
        container.appendChild(elChild);
    } else if (value === "Desktop application") {
        let elChild = document.createElement("div");
        elChild.innerHTML = `
                            <div>
                                <div class="form-floating mb-4">
                                    <input type="text" class="form-control" id="application_name" name="application_name"
                                           placeholder="application name">
                                    <label for="application_name">Application name</label>
                                </div>
                            </div>`;
        container.appendChild(elChild);
    } else if (value === "Game") {
        let elChild = document.createElement("div");
        elChild.innerHTML = `
                            <div>
                                <div class="form-floating mb-4">
                                    <input type="text" class="form-control" id="game_name" name="game_name"
                                           placeholder="game name">
                                    <label for="game_name">Game name</label>
                                </div>
                                <div class="form-floating mb-4">
                                    <input type="text" class="form-control" id="game_developer" name="game_developer"
                                           placeholder="game developer">
                                    <label for="game_developer">Game developer</label>
                                </div>
                            </div>`;
        container.appendChild(elChild);
    }
};

function generatePasswordHandler() {
    $.ajax({
        type: 'GET',
        url: '/generate-password/',
        success: function (data) {
            document.getElementsByName('password')[0].value = data.password;
        }
    });
};

function toggleView(id) {
    const input = document.getElementById(id);
    const icon = document.getElementById(`icon-${id}`)
    if (input.type === "password") {
        input.type = "text";
        icon.classList.remove("fa-eye")
        icon.classList.add("fa-eye-slash")
    } else {
        input.type = "password";
        icon.classList.remove("fa-eye-slash")
        icon.classList.add("fa-eye")
    }
}

// fingerprint

    async function registerUser() {
        const response = await fetch('/home/register/');
        const options = await response.json();

        // Call WebAuthn API to register the user
        const credential = await navigator.credentials.create({
            publicKey: options
        });

        // Send the credential to your server for verification
        const result = await fetch('/home/complete-registration/', {
            method: 'POST',
            body: JSON.stringify(credential)
        });

        if (result.ok) {
            alert('Registration successful!');
        } else {
            alert('Registration failed');
        }
    }

    async function authenticateUser() {
        const response = await fetch('/home/authenticate/');
        const options = await response.json();

        // Call WebAuthn API to authenticate the user
        const credential = await navigator.credentials.get({
            publicKey: options
        });

        // Send the credential to your server for verification
        const result = await fetch('/home/complete-authentication/', {
            method: 'POST',
            body: JSON.stringify(credential)
        });

        if (result.ok) {
            // Fetch and display decrypted passwords
            const passwordResponse = await fetch('/home/get-decrypted-passwords/');
            const passwords = await passwordResponse.json();
            console.log(passwords);  // Display passwords
            alert('Authentication successful!');
        } else {
            alert('Authentication failed');
        }
    }
    
    
    async function viewPasswords() {
        const authResult = await authenticateUser();
        if (authResult.status === "authenticated") {
            const response = await fetch('/home/get-decrypted-passwords/');
            if (response.ok) {
                const data = await response.json();
                console.log("Decrypted passwords:", data.passwords);
                alert('Passwords fetched successfully!');
            } else {
                alert('Failed to fetch passwords. Ensure fingerprint authentication is complete.');
            }
        } else {
            alert('Fingerprint authentication failed.');
        }
    }
    
    async function authenticateBeforeViewing() {
        try {
            // Replace with your WebAuthn options generation endpoint
            const response = await fetch('/authenticate/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': '{{ csrf_token }}', // Ensure CSRF token is included
                }
            });
            const options = await response.json();

            // Trigger fingerprint authentication
            const credential = await navigator.credentials.get({
                publicKey: options,
            });

            // Send authentication response to the server
            const verificationResponse = await fetch('/complete_authentication(/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': '{{ csrf_token }}', // Ensure CSRF token is included
                },
                body: JSON.stringify(credential),
            });

            const verificationResult = await verificationResponse.json();

            if (verificationResult.success) {
                // If successful, redirect to "manage-passwords"
                window.location.href = "{% url 'manage-passwords' %}";
            } else {
                alert("Authentication failed. You cannot view the passwords.");
            }
        } catch (error) {
            console.error('Authentication error:', error);
            alert('Authentication failed. Please try again.');
        }
    }

