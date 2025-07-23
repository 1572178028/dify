from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import MetaData

POSTGRES_INDEXES_NAMING_CONVENTION = {
    "ix": "%(column_0_label)s_idx",
    "uq": "%(table_name)s_%(column_0_name)s_key",
    "ck": "%(table_name)s_%(constraint_name)s_check",
    "fk": "%(table_name)s_%(column_0_name)s_fkey",
    "pk": "%(table_name)s_pkey",
}

metadata = MetaData(naming_convention=POSTGRES_INDEXES_NAMING_CONVENTION)

# ****** IMPORTANT NOTICE ******
#
# NOTE(QuantumGhost): Avoid directly importing and using `db` in modules outside of the
# `controllers` package.
#
# Instead, import `db` within the `controllers` package and pass it as an argument to
# functions or class constructors.
#
# Directly importing `db` in other modules can make the code more difficult to read, test, and maintain.
#
# Whenever possible, avoid this pattern in new code.
# 注意（QuantumGhost）：请避免在 controllers 包之外的模块中直接导入和使用 db。
# 正确做法是在 controllers 包内导入 db，并将其作为参数传递给函数或类的构造方法。
# 在其他模块中直接导入 db 会导致代码更难阅读、测试和维护。
# 在新代码中，请尽量避免这种用法。

db = SQLAlchemy(metadata=metadata)
