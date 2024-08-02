<?php
session_start();

if (!isset($_SESSION['email'])) {
    header("Location: index.html");
    exit();
}

echo "Welcome, " . htmlspecialchars($_SESSION['email']);
?>
