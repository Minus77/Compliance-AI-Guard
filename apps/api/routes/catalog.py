from __future__ import annotations

from typing import Any

from fastapi import FastAPI

from compliance_guard.knowledge.glossary import DEFAULT_LOCALE


def register_routes(app: FastAPI, services: Any) -> None:
    @app.get("/api/glossary")
    def get_glossary(locale: str = DEFAULT_LOCALE) -> dict[str, Any]:
        """Plain-language vocabulary for every finding type, decision and term.

        Unauthenticated on purpose: it is static explanatory text with no case
        data in it, and the UI needs it before a user has done anything. Served
        from one file so the interface, the API and any report cannot drift into
        explaining the same term three different ways.
        """
        return services.glossary.payload(locale)

    @app.get("/api/master-data/products")
    def list_products(market: str | None = None) -> dict[str, Any]:
        """Products with the label version currently in force.

        Only the current version is offered. A picker that lists a retired label
        would let someone write against approval terms that no longer apply, which
        is an off-label claim the tool itself created.

        Unauthenticated like ``/api/glossary``: this is product reference data with
        no case content in it, and the editor needs it before anything is typed.
        """
        products = services.label_facts_store.products(market=market)
        return {
            "count": len(products),
            "markets": services.label_facts_store.markets(),
            "products": [
                {
                    "product_id": label.product_id,
                    "market": label.market,
                    "label_version": label.version,
                    "indication": label.indication,
                    "indication_id": label.indication_id,
                    "population": label.population,
                    "dose": label.dose,
                    "route": label.route,
                    "effective_from": (
                        label.effective_from.isoformat() if label.effective_from else None
                    ),
                }
                for label in products
            ],
        }
