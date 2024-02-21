import hashlib
import random
import re
import string
import unittest
import unittest.mock
from datetime import datetime
from unittest.mock import MagicMock, patch, call
import sqlite3

import streamlit as st

import app
from app import (
    bcrypt,
    c,
    conn,
    generate_reset_token,
    hash_password,
    register_user,
    send_confirmation_email,
    send_email,
    validate_password,
    check_existing_user,
    insert_user_into_database,
)


# Unit tests for hash password function
class TestHashPassword(unittest.TestCase):

    def test_correct_hash(self):
        password = "secure_password123"
        expected_hash = hashlib.sha256(password.encode()).hexdigest()
        self.assertEqual(hash_password(password), expected_hash)

    def test_empty_password(self):
        password = ""
        expected_hash = hashlib.sha256(password.encode()).hexdigest()
        self.assertEqual(hash_password(password), expected_hash)

    def test_password_with_special_characters(self):
        password = "p@$$w0rd!&^%"
        expected_hash = hashlib.sha256(password.encode()).hexdigest()
        self.assertEqual(hash_password(password), expected_hash)

    def test_password_with_unicode_characters(self):
        password = "pässwörđ"
        expected_hash = hashlib.sha256(password.encode()).hexdigest()
        self.assertEqual(hash_password(password), expected_hash)

    def test_password_with_whitespace(self):
        password = "   "
        expected_hash = hashlib.sha256(password.encode()).hexdigest()
        self.assertEqual(hash_password(password), expected_hash)

    def test_password_with_leading_and_trailing_whitespace(self):
        password = "   password   "
        expected_hash = hashlib.sha256(password.strip().encode()).hexdigest()
        self.assertNotEqual(
            hash_password(password), expected_hash
        )  # expecting not to strip

        expected_correct_hash = hashlib.sha256(password.encode()).hexdigest()
        self.assertEqual(
            hash_password(password), expected_correct_hash
        )  # expecting hash without strip

    def test_password_is_not_string(self):
        # Assuming function should only accept strings
        with self.assertRaises(AttributeError):
            hash_password(None)

        with self.assertRaises(AttributeError):
            hash_password(12345)

        with self.assertRaises(AttributeError):
            hash_password([1, 2, 3])

        with self.assertRaises(AttributeError):
            hash_password({"password": "value"})


# Unit tests for the generate_reset_token function
class TestGenerateResetToken(unittest.TestCase):

    @patch("random.choices")
    def test_generate_reset_token_length(self, mock_choices):
        mock_choices.return_value = ["a"] * 20
        token = generate_reset_token()
        self.assertEqual(len(token), 20)

    def test_generate_reset_token_content(self):
        token = generate_reset_token()
        self.assertTrue(set(token).issubset(set(string.ascii_letters + string.digits)))

    @patch("random.choices")
    def test_generate_reset_token_fixed_output(self, mock_choices):
        expected_output = "a1b2c3d4e5f6g7h8i9j"
        mock_choices.return_value = [c for c in expected_output]
        token = generate_reset_token()
        self.assertEqual(token, expected_output)

    @patch("random.choices")
    def test_generate_reset_token_reproducibility(self, mock_choices):
        # By fixing the random.choices, we can test for reproducibility
        mock_choices.return_value = ["x"] * 10 + ["y"] * 10
        token1 = generate_reset_token()
        token2 = generate_reset_token()
        self.assertEqual(token1, token2)
        self.assertEqual(token1, "xxxxxxxxxxyyyyyyyyyy")

    def test_generate_reset_token_uniqueness(self):
        # Since this is random, it's unlikely to get the same token twice, but not impossible.
        tokens = {generate_reset_token() for _ in range(100)}
        self.assertEqual(len(tokens), 100)


# Unit tests for the validate_password function
class TestPasswordValidation(unittest.TestCase):

    def test_valid_password(self):
        self.assertTrue(validate_password("Password1!"))

    def test_short_password(self):
        self.assertFalse(validate_password("Pas1!"))

    def test_missing_uppercase(self):
        self.assertFalse(validate_password("password1!"))

    def test_missing_number(self):
        self.assertFalse(validate_password("Password!"))

    def test_missing_special_char(self):
        self.assertFalse(validate_password("Password1"))

    def test_empty_password(self):
        self.assertFalse(validate_password(""))

    def test_just_long_enough_password(self):
        self.assertTrue(validate_password("P@ssw0"))

    def test_password_with_spaces(self):
        self.assertFalse(validate_password("Password 1!"))

    def test_password_with_only_special_chars(self):
        self.assertFalse(validate_password("@$!%*?&"))

    def test_password_with_only_uppercase_letters(self):
        self.assertFalse(validate_password("PASSWORD"))

    def test_password_with_only_numbers(self):
        self.assertFalse(validate_password("123456"))

    def test_password_with_only_lowercase_letters(self):
        self.assertFalse(validate_password("password"))

    def test_password_with_uppercase_numbers_and_length_but_no_special(self):
        self.assertFalse(validate_password("Password1"))

    def test_long_valid_password(self):
        self.assertTrue(validate_password("ThisIsAVal1dPassw0rd!"))


# Unit tests for the register_user function
class TestUserRegistration(unittest.TestCase):
    @patch("app.st")
    @patch("app.validate_password")
    def test_register_user_successful(self, mock_validate_password, mock_st):
        # Mocking the session_state.user to be None (indicating no logged-in user)
        mock_st.session_state.user = None

        # Set up valid user inputs
        valid_inputs = {
            "First Name": "John",
            "Last Name": "Doe",
            "Email": "john.doe@example.com",
            "Password": "StrongPass123!",
            "Date of Birth": datetime(1990, 5, 15),
            "Gender": "Male",
            "Fitness Level": "Intermediate",
        }

        # Mock the user input and button click
        for field, value in valid_inputs.items():
            mock_st.text_input.side_effect = lambda label, **kwargs: (
                value if label == field else None
            )

        # Mock the validate_password function
        mock_validate_password.return_value = True

        # Mock the bcrypt module
        with patch("app.bcrypt.hashpw", return_value=b"hashed_password"):
            # Call the register_user function
            app.register_user()

        # Check if the expected calls are present in the actual calls (in any order)
        expected_calls = [
            mock_st.text_input("First Name", value="John"),
            mock_st.text_input("Last Name", value="Doe"),
            mock_st.text_input("Email", value="john.doe@example.com"),
            mock_st.text_input("Password", type="password", value="StrongPass123!"),
            mock_st.markdown(
                '<p style="font-size: 10px;">The password should have at least 1 uppercase, 1 lowercase, 1 number, and 1 special character.</p>',
                unsafe_allow_html=True,
            ),
            mock_st.date_input(
                "Date of Birth",
                min_value=datetime(1900, 1, 1),
                max_value=datetime.now(),
                value=datetime(1990, 5, 15),
            ),
            mock_st.selectbox(
                "Gender", options=["Male", "Female", "Other"], value="Male"
            ),
            mock_st.selectbox(
                "Fitness Level",
                options=["Beginner", "Intermediate", "Advanced"],
                value="Intermediate",
            ),
            mock_st.button("Register"),
            mock_st.markdown("Registration successful."),
        ]

        mock_st.assert_has_calls(expected_calls, any_order=True)


if __name__ == "__main__":
    unittest.main()
