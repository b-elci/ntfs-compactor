import unittest
from unittest import mock

import compactor


class CompressionActionTests(unittest.TestCase):
    def test_uncompressed_file_is_compressed(self):
        self.assertEqual(compactor.compression_action(None, "lzx", "skip"), "compress")

    def test_skip_behavior_skips_any_compressed_file(self):
        self.assertEqual(
            compactor.compression_action("XPRESS4K", "lzx", "skip"),
            "skip",
        )

    def test_same_algorithm_is_not_reprocessed(self):
        self.assertEqual(
            compactor.compression_action("LZX", "lzx", "recompress_if_different"),
            "skip",
        )

    def test_different_algorithm_is_recompressed(self):
        self.assertEqual(
            compactor.compression_action("XPRESS4K", "lzx", "recompress_if_different"),
            "recompress",
        )

    def test_recompression_uses_force_switch(self):
        with mock.patch.object(compactor, "run_compact", return_value=(0, "")) as run:
            compactor.compact_compress_file(r"C:\data.bin", "lzx", force=True)

        run.assert_called_once_with(
            ["/c", "/i", "/f", "/exe:lzx", r"C:\data.bin"]
        )


if __name__ == "__main__":
    unittest.main()
