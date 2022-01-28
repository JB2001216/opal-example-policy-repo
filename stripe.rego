package app.stripe

import future.keywords.in

# By default, deny requests
default allow = false

allow {
	have_any_payment
    input.method == "GET"
    input.url == "account"
}

allow {
	have_any_product
    input.method == "GET"
    input.url == "blog"
}

allow {
	have_any_active_subscription
    input.method in ["GET", "POST"]
    input.url == "blog"
}

have_any_payment {
	id := data.users[input.user].id
	count(data.user_payments[id].payments) > 0
}

have_any_product {
	id := data.users[input.user].id
    products := data.user_products[id].products
	filtered = [prod | prod := products[_]; prod["type"] != "subscription"]
	count(filtered) > 0
}

have_any_active_subscription {
	id := data.users[input.user].id
	subscriptions := data.user_subscriptions[id].subscriptions
	filtered = [subscription | subscription := subscriptions[_]; subscription == "active"]
	count(filtered) > 0
}
