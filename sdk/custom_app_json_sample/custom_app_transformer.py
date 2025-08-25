import os
import argparse
import logging
import csv
import datetime
from typing import Generator
from andromeda.nonpublic.integrations.customapp.customapp_inventory_pb2 import CustomAppInventoryData
from andromeda.api.models.config import enums_pb2
from google.protobuf.json_format import MessageToJson
from dataclasses import asdict, dataclass, field




logger = logging.getLogger(__name__)


class CustomAppInventoryTransformer:
    """
    """
    def __init__(self):
        self.inventory = CustomAppInventoryData()

    def csv_batch_reader(self, csv_file: str, batch_size: int=100) -> Generator[list, None, None]:
        """ Read CSV file in batches """
        with open(csv_file, 'r', encoding="utf-8") as f:
            csv_reader = csv.DictReader(f)
            batch = []
            for row in csv_reader:
                batch.append(row)
                if len(batch) == batch_size:
                    yield batch
                    batch = []
            if batch:
                yield batch


    def _transform_custom_type1_inventory_csv_row(self, app_name_prefx: str, inventory: CustomAppInventoryData, row: dict, errors: list) -> None:
        non_permissions_keys = set([
            'id', 'isActive', 'firstName', 'lastName', 'email', 'opRoleId', 'employeeId', 'Manager', 'Department',
            'total active dates', 'createdDate', 'updatedDate', 'Total active permissions'
        ])
        username = row['email']
        user_id = row['employeeId'] if row['employeeId'] else username
        if not username:
            logger.error("Skipping row %s as username not set", row)
            errors.append(row)
            return

        user = inventory.users.get_or_create(username)
        user.id = user_id
        user.name = " ".join([row['firstName'], row['lastName']])
        user.status = enums_pb2.ENABLED
        user.username = username

        # TODO replace by the header mapper later
        role_name = row['opRoleId']
        if not role_name:
            role_name = f"{app_name_prefx.lower()}-{row['firstName'].lower()}-{row['lastName'].lower()}-role"
            role_type = enums_pb2.PolicyTypeMessage.CUSTOM_APP_USER_ROLE
        else:
            role_type = enums_pb2.PolicyTypeMessage.CUSTOM_APP_ROLE
        role = inventory.roles.get_or_create(role_name)
        role.id = role_name
        role.name = role_name
        role.type = role_type
        # get permissions from the row which are marked as true for the role. Ideally,
        # all the permissions when role_id is set should be true but added a check
        # to validate that.
        permissions = [k for k, v in row.items() if k not in non_permissions_keys and v == 'TRUE']
        if role.permissions and set(permissions) != set(role.permissions):
            logger.error("role %s with different permissions difference %s ",
                         role_name, set(permissions).difference(set(role.permissions)))
            errors.append(row)
            return
        role.permissions.extend(permissions)
        assignment_id = username + '_' + role_name
        if assignment_id in inventory.assignments:
            logger.error("skipping conflicting assignments %s", assignment_id)
            errors.append(row)
            return
        assignment = inventory.assignments[assignment_id]
        assignment.id= assignment_id
        assignment.principal_id = username
        assignment.principal_type = enums_pb2.PrincipalTypeMessage.HUMAN
        assignment.role_id = role_name
        for p in permissions:
            p_data = inventory.permissions.get_or_create(p)
            p_data.name = p

    def transform_custom_type1_inventory_csv(self, app_name_prefx: str, inventory_file: str) -> tuple[CustomAppInventoryData, list]:
        inventory = CustomAppInventoryData()
        errors = []
        for b in self.csv_batch_reader(inventory_file):
            for row in b:
                self._transform_custom_type1_inventory_csv_row(app_name_prefx, inventory, row, errors)
        return inventory, errors

    def transform(self, app_name_prefx: str, inventory_file: str, inventory_type: str) -> CustomAppInventoryData:
        transform_fn_name = "_".join(["transform", inventory_type.strip().lower()])
        logger.info("Transforming inventory %s: %s using %s", inventory_type, inventory_file, transform_fn_name)
        transform_fn = getattr(self, transform_fn_name)
        self.inventory, errors = transform_fn(app_name_prefx, inventory_file)
        if errors:
            logger.error("Following rows skipped in transforming inventory file %s",
                         inventory_file)
            for e in errors:
                logger.error("%s", e)
        return self.inventory

    def transform_and_export(self, app_name_prefx: str, inventory_file: str, inventory_type: str, output_dir: str) -> None:
        inventory = self.transform(app_name_prefx, inventory_file, inventory_type)
        date = datetime.datetime.now().replace(microsecond=0, second=0).isoformat()
        output_file = f"{output_dir}/{app_name_prefx}-{date}.json"
        # check if directory exists if not then create it
        summary = self.summarize(inventory)
        logger.info("Summary of inventory file: %s ouput to %s", inventory_file, output_file)
        for k, v in summary.items():
            logger.info("%s: %s", k, v)
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        with open(output_file, 'w', encoding="utf-8") as f:
            inventory_json = MessageToJson(inventory)
            f.write(inventory_json)
        return inventory

    def summarize(self, inventory: CustomAppInventoryData) -> dict:
        summary = {
            'users': len(inventory.users),
            'roles': len(inventory.roles),
            'assignments': len(inventory.assignments)
        }
        return summary



if __name__ == '__main__':
    HELP_STR = """
    This script converts different csv imports into andromeda custom inventory format
    Example:
        python3 custom_app_transformer.py --inventory_type=CUSTOM_TYPE1_INVENTORY_CSV --inventory_file=<> --output_dir=<default .>
    """

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description=(HELP_STR)
    )

    parser.add_argument('--app_name_prefix', '-a',
                        help='application name prefix')

    parser.add_argument('--inventory_file', '-i',
                        help='inventory file')

    parser.add_argument('--output_dir',
                        help='output dir', default='/tmp/customapp_export')

    parser.add_argument('--inventory_type', help='inventory type', default='CUSTOM_TYPE1_INVENTORY_CSV')

    args = parser.parse_args()

    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    # create formatter and add it to the handlers
    formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(module)s:%(funcName)s:%(lineno)s: %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    t = CustomAppInventoryTransformer()
    t.transform_and_export(args.app_name_prefix.strip(), args.inventory_file.strip(), args.inventory_type.strip(), args.output_dir.strip())
