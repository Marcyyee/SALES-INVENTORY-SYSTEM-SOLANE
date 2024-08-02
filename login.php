<?php
session_start();
require 'connect.php';

$emailError = "";
$passwordError = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = $_POST['email'];
    $password = $_POST['password'];

    // Check if email and password are provided
    if (empty($email)) {
        $emailError = "Email is required.";
    }
    if (empty($password)) {
        $passwordError = "Password is required.";
    }

    if (empty($emailError) && empty($passwordError)) {
        // Prepare and execute SQL statement
        $stmt = $conn->prepare("SELECT password FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows == 1) {
            $stmt->bind_result($hashed_password);
            $stmt->fetch();

            // Verify the password
            if (password_verify($password, $hashed_password)) {
                $_SESSION['email'] = $email;
                header("Location: welcome.php"); // Redirect to a welcome page
                exit();
            } else {
                $passwordError = "Invalid email or password.";
            }
        } else {
            $emailError = "Invalid email or password.";
        }

        $stmt->close();
    }

    $conn->close();
}
?>
