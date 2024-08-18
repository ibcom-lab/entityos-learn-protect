mydigitalstructure Node.js module
====================================

Node.js module for mydigitalstructure.cloud

Makes it easy to init your node app onto the mydigitalstructure.cloud platform / API and send requests.

> http://mydigitalstructure.cloud

> http://docs.mydigitalstructure.cloud/gettingstarted_nodejs

> npm install mydigitalstucture

> Example app; https://github.com/ibcom/mydigitalstructure-sdk-nodejs

Version 2.0.0
-------------

**Initialise;**

`var mydigitalstructure = require('mydigitalstructure');`

Controller methods:
- mydigitalstructure.add({name:, note:, code:});
- mydigitalstructure.invoke(name, parameters for controller, data for controller);

<!-- end of the list -->

Local data storage methods:
- mydigitalstructure.set({scope:, context:, name:, value:});
- mydigitalstructure.get({scope:, context:, name:});

<!-- end of the list -->

Cloud data storage methods:
- mydigitalstructure.cloud.save({object:, data:, callback:});
- mydigitalstructure.cloud.retrieve({object:, data:, callback:});
- mydigitalstructure.cloud.invoke({object:, data:, callback:});

<!-- end of the list -->
