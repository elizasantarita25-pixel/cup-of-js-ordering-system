
from decimal import Decimal


# ==============================
# USER BASE CLASS
# ==============================

class User:

    def __init__(
        self,
        user_id,
        full_name,
        username,
        email,
        password_hash
    ):
        self._user_id = user_id
        self._full_name = full_name
        self._username = username
        self._email = email
        self._password_hash = password_hash

    @property
    def user_id(self):
        return self._user_id

    @property
    def full_name(self):
        return self._full_name

    @property
    def username(self):
        return self._username

    @property
    def email(self):
        return self._email

    @property
    def role(self):
        return "user"

    def get_account_info(self):
        return {
            "user_id": self.user_id,
            "full_name": self.full_name,
            "username": self.username,
            "email": self.email,
            "role": self.role
        }


# ==============================
# CUSTOMER CLASS
# ==============================

class Customer(User):

    @property
    def role(self):
        return "customer"

    def can_place_order(self):
        return True


# ==============================
# ADMIN CLASS
# ==============================

class Admin(User):

    @property
    def role(self):
        return "admin"

    def can_manage_system(self):
        return True


# ==============================
# PRODUCT VARIANT CLASS
# ==============================

class ProductVariant:

    def __init__(
        self,
        variant_id,
        product_name,
        variant_name,
        price,
        stock_quantity,
        low_stock_threshold=5,
        is_available=True
    ):
        self.variant_id = variant_id
        self.product_name = product_name
        self.variant_name = variant_name
        self.price = Decimal(str(price))
        self.stock_quantity = int(stock_quantity)
        self.low_stock_threshold = int(low_stock_threshold)
        self.is_available = bool(is_available)

    @property
    def stock_status(self):

        if self.stock_quantity == 0:
            return "Out of Stock"

        if self.stock_quantity <= self.low_stock_threshold:
            return "Low Stock"

        return "In Stock"

    def has_sufficient_stock(self, quantity):
        return (
            quantity > 0
            and self.stock_quantity >= quantity
        )

    def add_stock(self, quantity):

        if quantity <= 0:
            raise ValueError("Quantity must be greater than zero.")

        self.stock_quantity += quantity

    def deduct_stock(self, quantity):

        if not self.has_sufficient_stock(quantity):
            raise ValueError("Insufficient stock.")

        self.stock_quantity -= quantity


# ==============================
# ADDON CLASS
# ==============================

class Addon:

    def __init__(
        self,
        addon_id,
        addon_name,
        unit_price,
        quantity=1
    ):
        self.addon_id = addon_id
        self.addon_name = addon_name
        self.unit_price = Decimal(str(unit_price))
        self.quantity = int(quantity)

    @property
    def subtotal(self):
        return self.unit_price * self.quantity


# ==============================
# ORDER ITEM CLASS
# ==============================

class OrderItem:

    def __init__(
        self,
        product_name,
        variant_name,
        quantity,
        unit_price,
        addons=None
    ):
        self.product_name = product_name
        self.variant_name = variant_name
        self.quantity = int(quantity)
        self.unit_price = Decimal(str(unit_price))
        self.addons = addons or []

    @property
    def subtotal(self):

        addon_total = sum(
            (addon.subtotal for addon in self.addons),
            Decimal("0.00")
        )

        return (
            self.unit_price + addon_total
        ) * self.quantity


# ==============================
# ORDER CLASS
# ==============================

class Order:

    def __init__(
        self,
        order_id,
        items=None,
        fulfillment_method="pickup",
        delivery_fee=0
    ):
        self.order_id = order_id
        self.items = items or []
        self.fulfillment_method = fulfillment_method
        self.delivery_fee = Decimal(str(delivery_fee))

    @property
    def subtotal(self):
        return sum(
            (item.subtotal for item in self.items),
            Decimal("0.00")
        )

    @property
    def total_amount(self):
        return self.subtotal + self.delivery_fee

    def add_item(self, item):
        self.items.append(item)
