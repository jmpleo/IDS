
const socket = new WebSocket('ws://' + window.location.host + window.location.pathname)

socket.onopen = function() {
    console.log('ws connection success');
};


const notification_template = `<a href="/alerts" class="list-group-item list-group-item-action">
    <div class="row align-items-center">
        <div class="col ml--2">
        <div class="d-flex justify-content-between align-items-center">
            <div>
                <h4 class="mb-0 text-sm"> {{source}} </h4>
            </div>
            <div class="text-right text-muted">
                <small> {{timestamp}} </small>
            </div>
        </div>
        <p class="text-sm mb-0"> {{description}} </p>
        </div>
    </div>
</a>
`


socket.onmessage = function(event) {
    const data = JSON.parse(event.data);
    document.getElementById("notifications").innerHTML =
        document.getElementById("notifications").innerHTML
        + notification_template
            .replace("{{source}}", data.source_ip)
            .replace("{{description}}", data.description)
            .replace("{{timestamp}}", data.timestamp);

    console.log(data);
};

socket.onclose = function(event) {
    console.log('connection close');
};

socket.onerror = function(error) {
    console.error('error:', error);
};

