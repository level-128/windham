import sympy as sp

n = sp.symbols('n')

def get_precise_bounds(n_val):
    exp_val = sp.exp(n_val)
    lower_bound = sp.floor(exp_val * sp.Rational(85, 100))
    upper_bound = sp.ceiling(exp_val * sp.Rational(115, 100))
    return lower_bound, upper_bound

c_array = "uint64_t bounds[20][2] = {\n"

for n_val in range(1, 31):
    lower, upper = get_precise_bounds(n_val)
    c_array += f"    {{{lower}, {upper}}},\n"

c_array = c_array.rstrip(',\n') + "\n};"

print(c_array)
