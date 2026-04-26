"""English given-name data — top US given names by SSA frequency.

Source: U.S. Social Security Administration, Top Names by Decade
        https://www.ssa.gov/oact/babynames/decades/
License: Public domain (17 USC § 105 — works of the U.S. federal government).

Coverage: ~250 most-frequent given names from the past century. Combined male
and female names. Used to boost confidence on surname-anchored matches in
``lang/en/person.py`` (a match like "Quincy Smith" gets confidence 0.9 because
"Quincy" is not in this list; "John Smith" gets 1.0 because "John" is).

Long-tail names should be supplied via the ``names=[...]`` parameter or
detected via NER (``mode="ner"``).
"""

from __future__ import annotations

GIVEN_NAMES = (
    # Top male names (mid-century to present)
    "James", "John", "Robert", "Michael", "William",
    "David", "Richard", "Joseph", "Thomas", "Charles",
    "Christopher", "Daniel", "Matthew", "Anthony", "Donald",
    "Mark", "Paul", "Steven", "Andrew", "Kenneth",
    "Joshua", "Kevin", "Brian", "George", "Edward",
    "Ronald", "Timothy", "Jason", "Jeffrey", "Ryan",
    "Jacob", "Gary", "Nicholas", "Eric", "Jonathan",
    "Stephen", "Larry", "Justin", "Scott", "Brandon",
    "Benjamin", "Samuel", "Gregory", "Frank", "Alexander",
    "Raymond", "Patrick", "Jack", "Dennis", "Jerry",
    "Tyler", "Aaron", "Jose", "Henry", "Adam",
    "Douglas", "Nathan", "Peter", "Zachary", "Kyle",
    "Walter", "Harold", "Jeremy", "Ethan", "Carl",
    "Keith", "Roger", "Gerald", "Christian", "Terry",
    "Sean", "Arthur", "Austin", "Noah", "Lawrence",
    "Jesse", "Joe", "Bryan", "Billy", "Jordan",
    "Albert", "Dylan", "Bruce", "Willie", "Gabriel",
    "Alan", "Juan", "Logan", "Wayne", "Roy",
    "Ralph", "Randy", "Eugene", "Vincent", "Russell",
    "Louis", "Bobby", "Philip", "Johnny",
    # Top female names (mid-century to present)
    "Mary", "Patricia", "Jennifer", "Linda", "Elizabeth",
    "Barbara", "Susan", "Jessica", "Sarah", "Karen",
    "Lisa", "Nancy", "Betty", "Margaret", "Sandra",
    "Ashley", "Kimberly", "Emily", "Donna", "Michelle",
    "Carol", "Amanda", "Dorothy", "Melissa", "Deborah",
    "Stephanie", "Rebecca", "Sharon", "Laura", "Cynthia",
    "Kathleen", "Amy", "Shirley", "Angela", "Helen",
    "Anna", "Brenda", "Pamela", "Nicole", "Emma",
    "Samantha", "Katherine", "Christine", "Debra", "Rachel",
    "Catherine", "Carolyn", "Janet", "Ruth", "Maria",
    "Heather", "Diane", "Virginia", "Julie", "Joyce",
    "Victoria", "Olivia", "Kelly", "Christina", "Lauren",
    "Joan", "Evelyn", "Judith", "Megan", "Cheryl",
    "Andrea", "Hannah", "Martha", "Jacqueline", "Frances",
    "Gloria", "Ann", "Teresa", "Kathryn", "Sara",
    "Janice", "Jean", "Alice", "Madison", "Doris",
    "Abigail", "Julia", "Judy", "Grace", "Denise",
    "Amber", "Marilyn", "Beverly", "Danielle", "Theresa",
    "Sophia", "Marie", "Diana", "Brittany", "Natalie",
    "Isabella", "Charlotte", "Rose", "Alexis", "Kayla",
)

GIVEN_NAME_SET = frozenset(GIVEN_NAMES)
