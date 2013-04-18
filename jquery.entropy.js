/**
* Password Entropy
*
* This jQuery plug-in is built to give an estimate of the entropy of a password.
* Initial calculations assume a randomly generated password is used, and then
* applies a heuristics approach to penalize some common problems that arise
* with human-generated passwords.
*
* Some of the patterns used for creating the estimates are based on data collected
* in the paper "Testing Metrics for Password Creation Policies by Attacking Large
* Sets of Revealed Passwords" by Weir et. al. and can be recommended as further
* reading for those interested.
*
* The default blacklisted passwords are based on lists downloaded from
* http://www.skullsecurity.org/ and then compiled to match the purpose of this
* plug-in.
*
* MIT LICENSE
* Copyright (C) 2011 by Erik Brännström
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* THE SOFTWARE.
*/

(function( $ ){

    $.fn.passwordEntropy = function(options) {

        var log2 = function (value) {
            return Math.log(value)/Math.log(2)
        };

        var defaults = {
            'display'     : '.strength',
            'functions'    : [
                function(entropy, password) {
                    // Penalize passwords with:
                    //  - only letters followed by 1 to 3 digits
                    //  - beginning with single uppercase followed by lowercase
                    //  - only letters followed by a single special character
                    if( password.match(/^[a-zA-Z]+[0-9]{1,3}$/)
                    ||  password.match(/^[A-Z][a-z]+$/)
                    ||  password.match(/^[a-zA-Z]+[^a-zA-Z0-9]$/) )
                        return entropy - 8;
                    else
                        return entropy;
                },
                function(entropy, password) {
                    // Make sure password is not in blacklist
                    if(settings.blacklist.length == 0 || jQuery.inArray(password.toLowerCase(), settings.blacklist) === -1)
                        return entropy;

                    return log2(settings.blacklist.length);
                },
                function(entropy, password) {
                    // Decrease entropy when password contains repeated characters
                    var repeats = 0;
                    for (var i = 0; i < password.length-1; i++) {
                        if (password.charAt(i) === password.charAt(i+1)) {
                            repeats += 1;
                        }
                    }
                    return entropy - repeats*3;
                }
            ],
            'strings'   : ['Very Weak', 'Weak', 'Acceptable', 'Good', 'Strong', 'Very Strong'],
            'classes'   : ['very-weak', 'weak', 'Acceptable', 'good', 'strong', 'very-strong'],
            // Default blacklist contains 504 based on Twitters disallowed and the 500 worst passwords.
            'blacklist' : ["111111", "11111111", "112233", "121212", "123123", "123456", "1234567", "12345678", "131313", "232323", "654321", "666666", "696969", "777777", "7777777", "8675309", "987654", "aaaaaa", "abc123", "abcdef", "abgrtyu", "access", "access14", "action", "albert", "alexis", "amanda", "amateur", "andrea", "andrew", "angela", "angels", "animal", "anthony", "apollo", "apples", "arsenal", "arthur", "asdfgh", "ashley", "august", "austin", "badboy", "bailey", "banana", "barney", "baseball", "batman", "beaver", "beavis", "bigdaddy", "bigdog", "birdie", "bitches", "biteme", "blazer", "blonde", "blondes", "bond007", "bonnie", "booboo", "booger", "boomer", "boston", "brandon", "brandy", "braves", "brazil", "bronco", "broncos", "bulldog", "buster", "butter", "butthead", "calvin", "camaro", "cameron", "canada", "captain", "carlos", "carter", "casper", "charles", "charlie", "cheese", "chelsea", "chester", "chicago", "chicken", "cocacola", "coffee", "college", "compaq", "computer", "cookie", "cooper", "corvette", "cowboy", "cowboys", "crystal", "dakota", "dallas", "daniel", "danielle", "debbie", "dennis", "diablo", "diamond", "doctor", "doggie", "dolphin", "dolphins", "donald", "dragon", "dreams", "driver", "eagle1", "eagles", "edward", "einstein", "erotic", "extreme", "falcon", "fender", "ferrari", "firebird", "fishing", "florida", "flower", "flyers", "football", "forever", "freddy", "freedom", "gandalf", "gateway", "gators", "gemini", "george", "giants", "ginger", "golden", "golfer", "gordon", "gregory", "guitar", "gunner", "hammer", "hannah", "hardcore", "harley", "heather", "helpme", "hockey", "hooters", "horney", "hotdog", "hunter", "hunting", "iceman", "iloveyou", "internet", "iwantu", "jackie", "jackson", "jaguar", "jasmine", "jasper", "jennifer", "jeremy", "jessica", "johnny", "johnson", "jordan", "joseph", "joshua", "junior", "justin", "killer", "knight", "ladies", "lakers", "lauren", "leather", "legend", "letmein", "little", "london", "lovers", "maddog", "madison", "maggie", "magnum", "marine", "marlboro", "martin", "marvin", "master", "matrix", "matthew", "maverick", "maxwell", "melissa", "member", "mercedes", "merlin", "michael", "michelle", "mickey", "midnight", "miller", "mistress", "monica", "monkey", "monster", "morgan", "mother", "mountain", "muffin", "murphy", "mustang", "naked", "nascar", "nathan", "naughty", "ncc1701", "newyork", "nicholas", "nicole", "nipple", "nipples", "oliver", "orange", "packers", "panther", "panties", "parker", "password", "password1", "password12", "password123", "patrick", "peaches", "peanut", "pepper", "phantom", "phoenix", "player", "please", "pookie", "porsche", "prince", "princess", "private", "purple", "pussies", "qazwsx", "qwerty", "qwertyui", "rabbit", "rachel", "racing", "raiders", "rainbow", "ranger", "rangers", "rebecca", "redskins", "redsox", "redwings", "richard", "robert", "rocket", "rosebud", "runner", "rush2112", "russia", "samantha", "sammy", "samson", "sandra", "saturn", "scooby", "scooter", "scorpio", "scorpion", "secret", "sexsex", "shadow", "shannon", "shaved", "sierra", "silver", "skippy", "slayer", "smokey", "snoopy", "soccer", "sophie", "spanky", "sparky", "spider", "squirt", "srinivas", "startrek", "starwars", "steelers", "steven", "sticky", "stupid", "success", "summer", "sunshine", "superman", "surfer", "swimming", "sydney", "taylor", "tennis", "teresa", "tester", "testing", "theman", "thomas", "thunder", "thx1138", "tiffany", "tigers", "tigger", "tomcat", "topgun", "toyota", "travis", "trouble", "trustno1", "tucker", "turtle", "twitter", "united", "vagina", "victor", "victoria", "viking", "voodoo", "voyager", "walter", "warrior", "welcome", "whatever", "william", "willie", "wilson", "winner", "winston", "winter", "wizard", "xavier", "xxxxxx", "xxxxxxxx", "yamaha", "yankee", "yankees", "yellow", "zxcvbn", "zxcvbnm", "zzzzzz", "1234", "pussy", "12345", "pass", "fuckme", "6969", "fuck", "2000", "test", "love", "sexy", "asshole", "fuckyou", "1111", "enter", "fucker", "blowjob", "dick", "bitch", "hello", "black", "money", "horny", "girls", "john", "james", "mike", "blowme", "chris", "david", "fucking", "bigdick", "blue", "house", "jack", "golf", "bear", "tiger", "angel", "porno", "1212", "fish", "porn", "teens", "jason", "cumshot", "lover", "5150", "bubba", "2112", "fred", "xxxxx", "tits", "boobs", "penis", "white", "bigtits", "green", "super", "magic", "scott", "2222", "asdf", "video", "7777", "bill", "peter", "cock", "beer", "beach", "star", "frank", "dave", "11111", "steve", "viper", "ou812", "jake", "suckit", "buddy", "young", "lucky", "baby", "cunt", "brian", "mark", "4444", "bigcock", "happy", "booty", "fucked", "0", "fire", "chevy", "slut", "power", "paris", "rock", "xxxx", "dirty", "ford", "wolf", "alex", "eric", "movie", "great", "cool", "1313", "japan", "stars", "apple", "aaaa", "kevin", "matt", "4321", "4128", "shit", "3333", "cumming", "kitty", "cream", "kelly", "paul", "mine", "king", "5555", "eagle", "hentai", "smith", "enjoy", "girl", "qwert", "time", "women", "juice", "music", "billy", "6666"]
        };

        // Recursively merge user options with default settings and fix array merge
        var settings = $.extend({}, defaults, options);
        if(options) {
            settings.functions = defaults.functions.concat(options.functions);
            settings.blacklist = defaults.blacklist.concat(options.blacklist);
        }

        return this.each(function() {

            $(this).bind('keyup', function() {
                var psw = $(this).val();

                // Decide the number of characters in the character set
                var set = 0;
                if(psw.match(/[a-z]/))
                    set += 26;
                if(psw.match(/[A-Z]/))
                    set += 26;
                if(psw.match(/[0-9]/))
                    set += 10;
                if(psw.match(/[\._!\- @*#\/&]/)) // Most common special characters based on RockYou passwords
                    set += 10;
                if(psw.match(/[^a-zA-Z0-9\._!\- @*#\/&]/))
                    set += 23;

                // Calculate entropy in base 2
                var combinations = Math.pow(set, psw.length);
                var entropy = log2(combinations);

                // Run functions to modify password entropy
                for (var i in settings.functions) {
                    entropy = settings.functions[i](entropy, psw);
                }

                // Set message display
                var res = 0;
                if(entropy >= 60)
                    res = 5;
                else if(entropy >= 48)
                    res = 4;
                else if(entropy >= 36)
                    res = 3;
                else if(entropy >= 24)
                    res = 2;
                else if(entropy >= 12)
                    res = 1;

                // Display results
                $(settings.display).removeClass(settings.classes.join(' '))
                        .addClass(settings.classes[res])
                        .html(settings.strings[res]);
            });

        });
    };
})( jQuery );