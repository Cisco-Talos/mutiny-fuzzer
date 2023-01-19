from unittest.mock import patch
from unittest import TestCase

from backend.menu_functions import prompt, prompt_int, prompt_string, validate_number_range

class TestMenuFunctions(TestCase):
    def setUp(self):
        pass

    @patch('backend.menu_functions.get_input', return_value='y')
    def test_prompt_y(self, input):
        q = 'is test passing?'
        self.assertEqual(prompt(q), True)

    @patch('backend.menu_functions.get_input', return_value='n')
    def test_prompt_n(self, input):
        q = 'is test passing?'
        self.assertEqual(prompt(q), False)

    @patch('backend.menu_functions.get_input', return_value='')
    def test_prompt_default(self, input):
        q = 'is test passing?'
        self.assertEqual(prompt(q, default_index=0), True)

    @patch('backend.menu_functions.get_input', return_value='1')
    def test_prompt_int_valid(self, input):
        q = 'is test passing?'
        self.assertEqual(prompt_int(q), 1)

    @patch('backend.menu_functions.get_input', return_value='n')
    def test_prompt_int_no(self, input):
        q = 'is test passing?'
        self.assertEqual(prompt_int(q, allow_no=True), None)

    @patch('backend.menu_functions.get_input', return_value='')
    def test_prompt_int_none(self, input):
        q = 'is test passing?'
        self.assertEqual(prompt_int(q, allow_no=True), None)

    @patch('backend.menu_functions.get_input', return_value='')
    def test_prompt_int_default(self, input):
        q = 'is test passing?'
        self.assertEqual(prompt_int(q, default_response=3), 3)

    @patch('backend.menu_functions.get_input', return_value='test')
    def test_prompt_string(self, input):
        q = 'is test passing?'
        self.assertEqual(prompt_string(q), 'test')
        
    @patch('backend.menu_functions.get_input', return_value='')
    def test_prompt_string_default(self, input):
        q = 'is test passing?'
        self.assertEqual(prompt_string(q), 'n')

    @patch('backend.menu_functions.get_input', return_value='test')
    def test_prompt_string_with_validation(self, input):
        q = 'is test passing?'
        def validator(input_str):
            return len(input_str) > 1
        self.assertEqual(prompt_string(q, validate_func=validator), 'test')

    def test_validate_number_range_commas(self):
        input_str = '1,2,3'
        self.assertEqual(validate_number_range(input_str), [1,2,3])

    def test_validate_number_range_hyphens(self):
        input_str = '1,2-5'
        self.assertEqual(validate_number_range(input_str), [1,range(2,6)])

    def test_validate_number_range_single_number(self):
        input_str = '2'
        self.assertEqual(validate_number_range(input_str), [2])

    def test_validate_number_range_invalid(self):
        input_str = '1-3-5'
        self.assertEqual(validate_number_range(input_str), None)

    def test_validate_number_range_descending(self):
        input_str = '3,2,1'
        self.assertEqual(validate_number_range(input_str), [3,2,1])

    def test_validate_number_flatten(self):
        input_str = '1,2,3-5'
        self.assertEqual(validate_number_range(input_str), [1,2,range(3,6)])
