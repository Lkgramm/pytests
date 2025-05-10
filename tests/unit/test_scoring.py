import unittest
from src.api_scoring.scoring import get_score, get_interests

class TestScoring(unittest.TestCase):
    def setUp(self):
        # Мокаем хранилище, пока не тестируем реальное подключение
        self.store = None

    def test_get_score_phone_email(self):
        score = get_score(store=self.store, phone="79175002040", email="test@example.com")
        self.assertEqual(score, 3)

    def test_get_score_birthday_gender(self):
        score = get_score(store=self.store, birthday="01.01.1990", gender=1)
        self.assertEqual(score, 1.5)

    def test_get_score_first_last_name(self):
        score = get_score(store=self.store, first_name="John", last_name="Doe")
        self.assertEqual(score, 0.5)

    def test_get_score_combination(self):
        score = get_score(store=self.store,
                          phone="79175002040",
                          email="test@example.com",
                          birthday="01.01.1990",
                          gender=1,
                          first_name="John",
                          last_name="Doe")
        self.assertEqual(score, 5.0)

    def test_get_interests_returns_list_of_strings(self):
        interests = get_interests(store=self.store, cid=1)
        self.assertIsInstance(interests, list)
        self.assertTrue(all(isinstance(i, str) for i in interests))
        self.assertEqual(len(interests), 2)


def cases(cases_list):
    def decorator(test_func):
        def wrapper(self, *args):
            for idx, case in enumerate(cases_list):
                with self.subTest(case=case):
                    test_func(self, case)
        return wrapper
    return decorator


class TestScoringWithCases(unittest.TestCase):
    @cases([
        {"phone": "79175002040", "email": "test@example.com"},
        {"birthday": "01.01.1990", "gender": 1},
        {"first_name": "John", "last_name": "Doe"},
        {"phone": "79175002040", "email": "test@example.com", "birthday": "01.01.1990", "gender": 1},
    ])
    def test_get_score_with_multiple_cases(self, data):
        score = get_score(store=None, **data)
        self.assertGreaterEqual(score, 0)