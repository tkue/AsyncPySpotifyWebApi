# Readme

Still in progress 

The goal is to build a library in Python to interact with Spotify's web API that is able to manage 1,000's of API calls.<br>
Some existing libraries are synchronous and don't offer any performant solutions for this

<br>
General structure: route all API calls through an async queue and enable retries and any additional reliability-enhancement measures. 
Multiple calls for pagination will be seamlessly handled as well
<br>
For setup, put any credentials in the `.env` files<br>
`user_oauth.env` is set a bit manually, but can be built with the help of `auth_helper.py`
<br><br> 
Some use cases:
- Copy existing playlists (save Discover Weekly and Release Radar)
- Assist in building playlists by song characteristics (e.g. rising tempo to match a workout)