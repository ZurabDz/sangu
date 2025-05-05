# --- Original Code ---
def factorial(n):
  """
  Calculates the factorial of a non-negative integer n.
  n! = n * (n-1) * ... * 1
  0! = 1
  """
  if not isinstance(n, int) or n < 0:
    raise ValueError("Factorial is only defined for non-negative integers")
  elif n == 0:
    return 1
  else:
    result = 1
    # Loop from 1 up to n (inclusive)
    for i in range(1, n + 1):
      result *= i # Multiply result by current number
    return result

# Example usage:
num = 5
print(f"--- Original Code ---")
print(f"The factorial of {num} is {factorial(num)}")
print("-" * 20)


# --- Manually Obfuscated Code ---
def _f0(a):
  if not isinstance(a, int) or a < 0:
    raise ValueError("E1") # Error message slightly obscured
  elif a == 0:
    return 1
  else:
    b = 1
    for c in range(1, a + 1):
      b *= c
    return b

# Example usage (using the obfuscated function name):
val = 5
print(f"--- Manually Obfuscated Code ---")
print(f"Result for {val} is {_f0(val)}")
print("-" * 20)


# --- Simulated Automatically Obfuscated Code ---
# This simulates aggressive renaming and whitespace removal often seen in tools.
# Some tools might encode this further (e.g., using exec(bytes.fromhex(...).decode()))
def _x1a_2f(a_zA_Z0_9):
 _O0O = isinstance(a_zA_Z0_9,int)
 _I1I = a_zA_Z0_9
 if not _O0O or _I1I<0: raise ValueError('E2')
 elif _I1I==0: return 1
 else:
  _l1l=1
  for _oOo_ in range(1,_I1I+1):_l1l*=_oOo_
  return _l1l

# Example usage (using the obfuscated function name):
inp = 5
print(f"--- Automatically Obfuscated Code ---")
print(f"Output for {inp} is {_x1a_2f(inp)}")
print("-" * 20)