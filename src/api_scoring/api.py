#!/usr/bin/env python

import abc
import json
from datetime import datetime
import logging
import hashlib
import uuid
import re
from argparse import ArgumentParser
from http.server import BaseHTTPRequestHandler, HTTPServer
from .scoring import get_score, get_interests

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class ValidationError(Exception):
    pass


class BaseField(abc.ABC):
    def __init__(self, required=True, nullable=False):
        self.required = required
        self.nullable = nullable

    @abc.abstractmethod
    def validate(self, value):
        pass


class BaseRequestMeta(type):
    def __new__(cls, name, bases, attrs):
        fields = {}

        for key, value in attrs.items():
            if isinstance(value, BaseField):
                fields[key] = value

        for key in fields:
            del attrs[key]

        # Добавляем специальный атрибут _fields, содержащий все найденные поля
        attrs["_fields"] = fields
        return super().__new__(cls, name, bases, attrs)


class BaseRequest(metaclass=BaseRequestMeta):
    def __init__(self, data=None):
        self.data = data or {}
        self.errors = {}

    def is_valid(self):
        self.errors = {}
        for name, field in self._fields.items():
            value = self.data.get(name)
            try:
                cleaned_value = field.validate(value)
                setattr(self, name, cleaned_value)
            except ValidationError as e:
                self.errors[name] = str(e)
        return not self.errors


class CharField(BaseField):
    def validate(self, value):
        if self.required and value is None:
            raise ValidationError("This field is required")
        if not self.nullable and (value == "" or value is None):
            raise ValidationError("This field cannot be empty")
        if value is not None and not isinstance(value, str):
            raise ValidationError("Value must be a string")
        return value


class ArgumentsField(BaseField):
    def __init__(self, request_class, **kwargs):
        super().__init__(**kwargs)
        self.request_class = request_class

    def validate(self, value):
        if self.required and not value:
            raise ValidationError("Arguments are required")
        req = self.request_class()
        errors = {}
        data = value or {}
        for field_name in req.__class__.__dict__:
            field = getattr(req.__class__, field_name)
            if isinstance(field, BaseField):
                try:
                    val = field.validate(data.get(field_name))
                    setattr(req, field_name, val)
                except ValidationError as e:
                    errors[field_name] = str(e)
        if errors:
            raise ValidationError(json.dumps(errors))
        return req


class EmailField(CharField):
    def validate(self, value):
        super().validate(value)
        if value and "@" not in value:
            raise ValidationError("Invalid email format")
        return value


class PhoneField(BaseField):
    def validate(self, value):
        if self.required and value is None:
            raise ValidationError("This field is required")
        if not self.nullable and (value == "" or value is None):
            raise ValidationError("This field cannot be empty")
        if value is not None and not re.fullmatch(r"7\d{10}", str(value)):
            raise ValidationError("Phone must start with 7 and be 11 digits")
        return value


class DateField(BaseField):
    def validate(self, value):
        # Вызов super() проверяет required/nullable
        super().validate(value)

        if value is None or value == "":  # если nullable — можно вернуть None
            return None

        try:
            dt = datetime.strptime(value, "%d.%m.%Y")  # ✅ Парсим строку в datetime
            if (datetime.now() - dt).days > 70 * 365:
                raise ValidationError("Birthday can't be older than 70 years")
            return dt
        except ValueError:
            raise ValidationError("Date must be in DD.MM.YYYY format")


class BirthDayField(DateField):
    def validate(self, value):
        dt = super().validate(value)

        if dt and (datetime.now() - dt).days > 70 * 365:
            raise ValidationError("Birthday can't be older than 70 years")

        return dt


class GenderField(BaseField):
    def validate(self, value):
        if self.required and value is None:
            raise ValidationError("This field is required")
        if not self.nullable and (value is None or value == ""):
            raise ValidationError("This field cannot be empty")
        if value is not None and value not in (0, 1, 2):
            raise ValidationError("Gender must be 0, 1 or 2")
        return value


class ClientIDsField(BaseField):
    def validate(self, value):
        if self.required and (not value):
            raise ValidationError("This field is required")
        if not isinstance(value, list) or not all(isinstance(x, int) for x in value):
            raise ValidationError("Client IDs must be a list of integers")
        return value


class ClientsInterestsRequest(BaseRequest):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def validate_extra(self):
        # Этот метод нужен для совместимости с тестами
        return True


class OnlineScoreRequest(BaseRequest):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def validate_extra(self):
        valid_pairs = (
            (self.phone is not None and self.email),
            (self.first_name and self.last_name),
            (self.birthday is not None and self.gender is not None),
        )
        if not any(valid_pairs):
            raise ValidationError("At least one valid pair required")


class MethodRequest:
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    login = request.login
    token = request.token
    account = request.account

    logging.info(f"Check auth for login={login}, token={token}, account={account}")

    if login == ADMIN_LOGIN:
        current_hour = datetime.now().strftime("%Y%m%d%H")  # форматируем текущее время
        expected_token = hashlib.sha512(
            (current_hour + ADMIN_SALT).encode()
        ).hexdigest()
    else:
        expected_token = hashlib.sha512((account + login + SALT).encode()).hexdigest()

    logging.info(f"Expected token: {expected_token}")
    logging.info(f"Given token: {token}")
    logging.info(f"Auth success: {token == expected_token}")

    return token == expected_token


def method_handler(request, ctx, store):
    body = request.get("body", {})

    # 1. Валидируем MethodRequest (основные поля: login, token, method, arguments)
    method_req = MethodRequest()
    errors = {}

    for field_name in MethodRequest.__dict__:
        field = getattr(MethodRequest, field_name)
        if isinstance(field, BaseField):
            try:
                val = field.validate(body.get(field_name))
                setattr(method_req, field_name, val)
            except ValidationError as e:
                errors[field_name] = str(e)

    if errors:
        logging.warning(f"MethodRequest validation failed: {errors}")
        return {"error": errors}, INVALID_REQUEST

    # 2. Аутентификация
    logging.info(
        f"Authenticating user: login={method_req.login}, account={method_req.account}"
    )
    if not check_auth(method_req):
        logging.warning("Authentication failed")
        return "", FORBIDDEN
    else:
        logging.info("Authentication succeeded")

    # 3. Определяем тип запроса
    if method_req.method == "online_score":
        req_class = OnlineScoreRequest
    elif method_req.method == "clients_interests":
        req_class = ClientsInterestsRequest
    else:
        logging.warning(f"Unknown method: {method_req.method}")
        return "", NOT_FOUND

    # 4. Валидируем аргументы метода
    arguments = body.get("arguments", {})
    args = req_class(data=arguments)

    if not args.is_valid():
        logging.warning(f"Arguments validation failed: {args.errors}")
        return {"error": args.errors}, INVALID_REQUEST

    try:
        args.validate_extra()
    except ValidationError as e:
        logging.warning(f"Extra validation failed: {e}")
        return {"error": str(e)}, INVALID_REQUEST

    # 5. Обработка методов
    if method_req.method == "online_score":
        has_fields = [
            name
            for name, _ in args._fields.items()
            if getattr(args, name, None) is not None
        ]
        ctx["has"] = has_fields

        if method_req.is_admin:
            score = 42
        else:
            score = get_score(
                store=store,
                phone=args.phone,
                email=args.email,
                birthday=args.birthday,
                gender=args.gender,
                first_name=args.first_name,
                last_name=args.last_name,
            )
        return {"score": score}, OK

    elif method_req.method == "clients_interests":
        ctx["nclients"] = len(args.client_ids)
        interests = {
            str(cid): get_interests(store=store, cid=cid) for cid in args.client_ids
        }
        return interests, OK


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {"method": method_handler}
    store = None

    def get_request_id(self, headers):
        return headers.get("HTTP_X_REQUEST_ID", uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers["Content-Length"]))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info(
                "{}: {} {}".format(self.path, data_string, context["request_id"])
            )
            if path in self.router:
                try:
                    response, code = self.router[path](
                        {"body": request, "headers": self.headers}, context, self.store
                    )
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode("utf-8"))
        return


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-p", "--port", action="store", type=int, default=8080)
    parser.add_argument("-l", "--log", action="store", default=None)
    args = parser.parse_args()
    logging.basicConfig(
        filename=args.log,
        level=logging.INFO,
        format="[%(asctime)s] %(levelname).1s %(message)s",
        datefmt="%Y.%m.%d %H:%M:%S",
    )
    server = HTTPServer(("localhost", args.port), MainHTTPHandler)
    logging.info("Starting server at %s" % args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
