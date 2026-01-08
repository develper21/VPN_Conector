from setuptools import setup
from setuptools.extension import Extension
from Cython.Build import cythonize
import numpy

extensions = [
    Extension(
        "packet_processor",
        ["packet_processor.pyx"],
        include_dirs=[numpy.get_include()],
        extra_compile_args=['-O3', '-march=native'],
        language='c'
    )
]

setup(
    ext_modules=cythonize(extensions),
    zip_safe=False,
)
