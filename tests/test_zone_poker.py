
import unittest
import argparse
from zone_poker import setup_parser

class TestZonePoker(unittest.TestCase):
    def test_setup_parser(self):
        parser = setup_parser()
        self.assertIsInstance(parser, argparse.ArgumentParser)
        # Test a few arguments
        args = parser.parse_args(['example.com', '--all', '--export'])
        self.assertEqual(args.domain, 'example.com')
        self.assertTrue(args.all)
        self.assertTrue(args.export)

if __name__ == '__main__':
    unittest.main()
