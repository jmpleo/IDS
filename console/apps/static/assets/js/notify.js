
const socket = new WebSocket('ws://' + window.location.host + window.location.pathname)

socket.onopen = function() {
    console.log('ws connection success');
};


const alert_template = `
<a href="/alerts" class="list-group-item m-1 list-group-item-action">
  <div class="row align-items-center">
    <div class="col ml--2">
      <div class="d-flex justify-content-between align-items-center">
        <div>
          <h4 class="text">
            <i class="ni ni-notification-70 text-danger"></i>
            <span class="text-lg bg-secondary rounded p-1">
            {{source}}
            </span>
            <i class="ni ni-bold-right text-dark"></i>
            <span class="text-lg bg-secondary rounded p-1">
            {{destination}}
            </span>
          </h4>
          <small class="text-sm text-dark bg-{{color}} rounded p-1"> {{datetime}} </small>
        </div>
      </div>
      <p class="text-sm mb-0"> {{description}} </p>
    </div>
  </div>
</a>
`

const notification_template = `
<a href="/alerts" class="list-group-item m-1 list-group-item-action">
  <div class="row align-items-center">
    <div class="col ml--2">
      <div class="d-flex justify-content-between align-items-center">
        <div>
          <h4 class="text">
            <i class="ni ni-notification-70 text-danger"></i>
            <span class="text-lg bg-{{color}} rounded p-1">
            {{source}}
            </span>
          </h4>
        </div>
      </div>
      <small class="text-sm text-dark"> {{datetime}} </small>
    </div>
  </div>
</a>
`

const notification_button = document.getElementById("notification-dropdown");
const colors = [
    "pink",
    "orange",
    "yellow",
    "green",
    "teal",
    "cyan",
    "light",
    "info",
    "light",
]

socket.onmessage = function(event) {
    const data = JSON.parse(event.data);
    const item_color = colors[Math.floor(Math.random() * colors.length)];
    const alert_item = alert_template
        .replace("{{source}}", data.source)
        .replace("{{destination}}", data.destination)
        .replace("{{description}}", data.description)
        .replace("{{datetime}}", Date(data.datetime))
        .replace("{{color}}", item_color);

    const notification_item = notification_template
        .replace("{{source}}", data.source)
        .replace("{{datetime}}", Date(data.datetime))
        .replace("{{color}}", item_color);


    document.getElementById("notifications").innerHTML = notification_item
        + document.getElementById("notifications").innerHTML;

    document.getElementById("notifications-list").innerHTML = alert_item
        + document.getElementById("notifications-list").innerHTML;

    if (notification_button.parentElement.classList.contains("show") == false) {
        notification_button.click();
    }

    console.log(data);
};

socket.onclose = function(event) {
    console.log('connection close');
};

socket.onerror = function(error) {
    console.error('error:', error);
};

