import pytest
import requests
import responses

from pyitau.main import ROUTER_URL, Itau
from pyitau.pages import AuthenticatedHomePage, CheckingAccountMenu, MenuPage


@pytest.fixture
def itau():
    return Itau('0000', '12345', '6', '123456')


@pytest.fixture
def authenticated_home_page(response_authenticated_home):
    return AuthenticatedHomePage(response_authenticated_home)


@pytest.fixture
def menu_page(response_menu):
    return MenuPage(response_menu)


def test_init():
    agency = '0000'
    account = '12345'
    account_digit = '6'
    password = '123456'

    itau = Itau(agency, account, account_digit, password)

    assert itau.agency == agency
    assert itau.account == account
    assert itau.account_digit == account_digit
    assert itau.password == password
    assert isinstance(itau._session, requests.Session)


@responses.activate
def test_menu_page(authenticated_home_page, itau, response_menu):
    itau._home = authenticated_home_page
    request = responses.post(
        ROUTER_URL,
        body=response_menu,
        match=[
            responses.matchers.header_matcher(
                {"op": authenticated_home_page.op, "segmento": "VAREJO"}
            )
        ],
    )

    assert itau._menu_page == MenuPage(response_menu)
    assert itau._menu_page == MenuPage(response_menu)

    assert request.call_count == 1


@responses.activate
def test_checking_menu_page(menu_page, itau, response_checking_account_menu):
    itau._menu_page = menu_page

    request = responses.post(
        ROUTER_URL,
        body=response_checking_account_menu,
        match=[
            responses.matchers.header_matcher(
                {"op": menu_page.checking_account_op}
            )
        ],
    )

    assert itau._checking_menu_page == CheckingAccountMenu(response_checking_account_menu)
    assert itau._checking_menu_page == CheckingAccountMenu(response_checking_account_menu)

    assert request.call_count == 1
