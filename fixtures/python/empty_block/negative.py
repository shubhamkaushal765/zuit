# Fixture: negative cases for MAINT013-empty-block (Python)
# None of the following should produce a finding.

from abc import abstractmethod
from typing import overload, Protocol

x = 1

# Non-empty if
if x:
    print(x)

# Non-empty for
for i in range(10):
    print(i)

# Non-empty while
while False:
    print("never")


class Base:
    @abstractmethod
    def method(self) -> None:
        pass  # abstractmethod stub — skip


class Foo:
    @overload
    def bar(self, x: int) -> int:
        ...  # overload stub — skip


class MyProto(Protocol):
    def proto_method(self) -> None:
        ...  # Protocol stub — skip
