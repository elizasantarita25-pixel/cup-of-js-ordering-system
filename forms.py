
from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    PasswordField,
    SubmitField,
    TextAreaField,
    SelectField,
    BooleanField,
    DecimalField,
    IntegerField
)
from wtforms.validators import (
    DataRequired,
    Email,
    Length,
    EqualTo,
    NumberRange
)


# =========================
# REGISTRATION FORM
# =========================

class RegistrationForm(FlaskForm):

    full_name = StringField("Full Name", validators=[
        DataRequired(message="Full name is required."),
        Length(max=150)
    ])

    username = StringField("Username", validators=[
        DataRequired(message="Username is required."),
        Length(min=4, max=50)
    ])

    email = StringField("Email Address", validators=[
        DataRequired(message="Email is required."),
        Email(message="Enter a valid email address."),
        Length(max=100)
    ])

    password = PasswordField("Password", validators=[
        DataRequired(message="Password is required."),
        Length(
            min=8,
            message="Password must be at least 8 characters."
        )
    ])

    confirm_password = PasswordField("Confirm Password", validators=[
        DataRequired(message="Please confirm your password."),
        EqualTo("password", message="Passwords do not match.")
    ])

    submit = SubmitField("Create Account")


# =========================
# LOGIN FORM
# =========================

class LoginForm(FlaskForm):

    username = StringField("Username or Email", validators=[
        DataRequired(message="Username or email is required.")
    ])

    password = PasswordField("Password", validators=[
        DataRequired(message="Password is required.")
    ])

    submit = SubmitField("Log In")


# =========================
# CATEGORY FORM
# =========================

class CategoryForm(FlaskForm):

    category_name = StringField("Category Name", validators=[
        DataRequired(message="Category name is required."),
        Length(max=100)
    ])

    description = TextAreaField("Description", validators=[
        Length(max=255)
    ])

    submit = SubmitField("Save Category")


# =========================
# PRODUCT FORM
# =========================

class ProductForm(FlaskForm):

    category_id = SelectField(
        "Category",
        coerce=int,
        validators=[
            DataRequired(message="Please select a category.")
        ]
    )

    product_name = StringField("Product Name", validators=[
        DataRequired(message="Product name is required."),
        Length(max=150)
    ])

    description = TextAreaField("Description", validators=[
        Length(max=255)
    ])

    is_available = BooleanField("Available for Ordering")

    submit = SubmitField("Save Product")


# =========================
# PRODUCT VARIANT FORM
# =========================

class ProductVariantForm(FlaskForm):

    product_id = SelectField(
        "Product",
        coerce=int,
        validators=[
            DataRequired(message="Please select a product.")
        ]
    )

    variant_name = StringField("Variant Name", validators=[
        DataRequired(message="Variant name is required."),
        Length(max=100)
    ])

    price = DecimalField(
        "Price",
        places=2,
        validators=[
            DataRequired(message="Price is required."),
            NumberRange(
                min=0,
                message="Price cannot be negative."
            )
        ]
    )

    low_stock_threshold = IntegerField(
        "Low Stock Threshold",
        validators=[
            DataRequired(message="Low-stock threshold is required."),
            NumberRange(
                min=0,
                message="Threshold cannot be negative."
            )
        ]
    )

    is_available = BooleanField("Available for Ordering")

    submit = SubmitField("Save Variant")

class InventoryForm(FlaskForm):
    variant_id = SelectField(
        "Product Variant",
        coerce=int,
        validators=[
            DataRequired(message="Please select a product variant.")
        ]
    )

    transaction_type = SelectField(
        "Transaction Type",
        choices=[
            ("stock_in", "Stock In"),
            ("adjustment_increase", "Stock Adjustment - Increase"),
            ("adjustment_decrease", "Stock Adjustment - Decrease")
        ],
        validators=[
            DataRequired(message="Please select a transaction type.")
        ]
    )

    quantity = IntegerField(
        "Quantity",
        validators=[
            DataRequired(message="Quantity is required."),
            NumberRange(
                min=1,
                message="Quantity must be at least 1."
            )
        ]
    )

    remarks = StringField(
        "Remarks",
        validators=[
            Length(max=255)
        ]
    )

    submit = SubmitField("Save Inventory Transaction")
    
    
class AddonForm(FlaskForm):
    category_id = SelectField(
        "Category",
        coerce=int,
        validators=[
            DataRequired(message="Please select a category.")
        ]
    )

    addon_name = StringField(
        "Add-on Name",
        validators=[
            DataRequired(message="Add-on name is required."),
            Length(max=100)
        ]
    )

    price = DecimalField(
        "Price",
        places=2,
        validators=[
            DataRequired(message="Price is required."),
            NumberRange(
                min=0,
                message="Price cannot be negative."
            )
        ]
    )

    is_available = BooleanField("Available")

    submit = SubmitField("Save Add-on")
    
    
class OrderForm(FlaskForm):
    order_type = SelectField(
        "Order Type",
        choices=[
            ("walk_in", "Walk-in"),
            ("online", "Online")
        ],
        validators=[
            DataRequired(message="Please select an order type.")
        ]
    )

    fulfillment_method = SelectField(
        "Fulfillment Method",
        choices=[
            ("pickup", "Pickup"),
            ("delivery", "Delivery")
        ],
        validators=[
            DataRequired(message="Please select a fulfillment method.")
        ]
    )

    payment_method = SelectField(
        "Payment Method",
        choices=[
            ("cash", "Cash"),
            ("gcash", "GCash")
        ],
        validators=[
            DataRequired(message="Please select a payment method.")
        ]
    )

    submit = SubmitField("Continue")


class OrderItemForm(FlaskForm):
    variant_id = SelectField(
        "Product Variant",
        coerce=int,
        validators=[
            DataRequired(message="Please select a product variant.")
        ]
    )

    quantity = IntegerField(
        "Quantity",
        validators=[
            DataRequired(message="Quantity is required."),
            NumberRange(
                min=1,
                message="Quantity must be at least 1."
            )
        ]
    )

    submit = SubmitField("Add Item")
    