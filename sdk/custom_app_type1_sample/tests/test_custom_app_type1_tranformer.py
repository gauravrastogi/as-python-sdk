"""
Test the custom app type1 transformer
"""
import logging
import json
from dataclasses import asdict
from deepdiff import DeepDiff
from sdk.custom_app_type1_sample.custom_app_type1_transformer import CustomAppSampleTransformer, CustomAppRoleAssignment


logger = logging.getLogger(__name__)

def test_transform_custom_type1_inventory_csv():
    """
    Test the custom app sample transformer
    """
    inventory_file = "beatles-custom-app.csv"
    csv_transformer = CustomAppSampleTransformer(
        app_name="beatles",
        inventory_file=inventory_file,
        output_dir="/tmp/customapp_export"
    )
    inventory, errors = csv_transformer.transform()
    assert inventory
    assert not errors, f"Errors: {errors}"
    inventory_dict = asdict(inventory)
    inventory_dict = csv_transformer.convert_to_andromeda_dict(inventory_dict)
    logger.debug("Inventory %s", json.dumps(inventory_dict, indent=2))
    with open('beatles-custom-app.json', 'r', encoding="utf-8") as f:
        expected_inventory = json.load(f)
        diff = DeepDiff(inventory_dict, expected_inventory, ignore_order=True)
        assert not diff, f"Inventory mismatch {diff}"

def test_inventory_invalid_permission_validation():
    """
    Test the inventory validation
    """
    inventory_file = "beatles-custom-app.csv"
    csv_transformer = CustomAppSampleTransformer(
        app_name="beatles",
        inventory_file=inventory_file,
        output_dir="/tmp/customapp_export"
    )
    # modify the inventory to be invalid
    inventory, errors = csv_transformer.transform()
    assert inventory
    assert not errors, f"Errors: {errors}"

    r1 = next(iter(inventory.roles.values()))
    r1.permissions.append("invalid_permission")
    try:
        csv_transformer.inventory_validation()
        assert False, "Expected ValueError"
    except ValueError as e:
        assert str(e).find("invalid_permission") != -1

def test_inventory_invalid_user():
    """
    Test the inventory validation
    """
    inventory_file = "beatles-custom-app.csv"
    csv_transformer = CustomAppSampleTransformer(
        app_name="beatles",
        inventory_file=inventory_file,
        output_dir="/tmp/customapp_export"
    )
    # modify the inventory to be invalid
    inventory, errors = csv_transformer.transform()
    assert inventory
    assert not errors, f"Errors: {errors}"

    u1 = next(iter(inventory.users.values()))
    u1.status = 'INVALID_STATUS'
    try:
        csv_transformer.inventory_validation()
        assert False, "Expected ValueError"
    except (ValueError, KeyError) as e:
        assert str(e).find("INVALID_STATUS") != -1

def test_inventory_invalid_assignment_validation():
    """
    Test the inventory validation
    """
    inventory_file = "beatles-custom-app.csv"
    csv_transformer = CustomAppSampleTransformer(
        app_name="beatles",
        inventory_file=inventory_file,
        output_dir="/tmp/customapp_export"
    )

    # modify the inventory to be invalid
    inventory, errors = csv_transformer.transform()
    assert inventory
    assert not errors, f"Errors: {errors}"

    invalid_assignment = CustomAppRoleAssignment(
        id="1",
        principalId="invalid_principal",
        principalType="HUMAN",
        roleId="1"
    )
    inventory.assignments[invalid_assignment.id] = invalid_assignment

    try:
        csv_transformer.inventory_validation()
        assert False, "Expected ValueError"
    except ValueError as e:
        assert str(e).find("invalid_principal") != -1
