'use strict';

class Workout {
  date = new Date();
  clicks = 0;

  constructor(coords, distance, duration, id) {
    // this.date = ...
    // this.id = ...
    this.id = id;
    this.coords = coords; // [lat, lng]
    this.distance = distance; // in km
    this.duration = duration; // in min
  }

  _setDescription() {
    // prettier-ignore
    const months = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];

    this.description = `${this.type[0].toUpperCase()}${this.type.slice(1)} on ${
        months[this.date.getMonth()]
    } ${this.date.getDate()}`;
  }

  click() {
    this.clicks++;
  }
}

class Cycling extends Workout {
  type = 'cycling';

  constructor(coords, distance, duration, batteryLevel, id, isOnline) {
    super(coords, distance, duration, id);
    this.batteryLevel = batteryLevel;
    this.isOnline = isOnline;
    // this.type = 'cycling';
    this.calcSpeed();
    this._setDescription();
  }

  calcSpeed() {
    // km/h
    this.speed = this.distance / (this.duration / 60);
    return this.speed;
  }
}

// const run1 = new Running([39, -12], 5.2, 24, 178);
// const cycling1 = new Cycling([39, -12], 27, 95, 523);
// console.log(run1, cycling1);

///////////////////////////////////////
// APPLICATION ARCHITECTURE
const form = document.querySelector('.form');
const containerWorkouts = document.querySelector('.workouts');
const inputType = document.querySelector('.form__input--type');
const inputDistance = document.querySelector('.form__input--distance');
const inputDuration = document.querySelector('.form__input--duration');
const inputCadence = document.querySelector('.form__input--cadence');
const inputElevation = document.querySelector('.form__input--elevation');

class App {
  #map;
  #mapZoomLevel = 13;
  #mapEvent;
  workouts = [];
  #coords;
  #marker1;
  #marker2;
  #marker3;
  #workout1;
  #workout2;
  #workout3;

  constructor() {
    // Get user's position
    this._getPosition();

    // Get data from local storage
    this._getLocalStorage();

    // Attach event handlers
    containerWorkouts.addEventListener('click', this._moveToPopup.bind(this));
  }

  _getPosition() {
    if (navigator.geolocation)
      navigator.geolocation.getCurrentPosition(
          this._loadMap.bind(this),
          function () {
            alert('Could not get your position');
          }
      );
  }

  _loadMap(position) {
    const { latitude } = position.coords;
    const { longitude } = position.coords;
    // console.log(`https://www.google.pt/maps/@${latitude},${longitude}`);

    const coords = [latitude, longitude];

    this.#map = L.map('map').setView(coords, this.#mapZoomLevel);

    // L.tileLayer('https://tile.thunderforest.com/cycle/{z}/{x}/{y}.png?apikey=0773e400f0854b86be8458cb0ed761d3', {
    //   attribution:
    //     'Maps &copy; <a href = "www.thunderforest.com">Thunderforest</a> Data &copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
    // }).addTo(this.#map);

    L.tileLayer('https://{s}.tile.openstreetmap.fr/hot/{z}/{x}/{y}.png', {
      attribution:
          '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
    }).addTo(this.#map);

    this.workouts.forEach(work => {
      this._renderWorkoutMarker(work);
    });

    this.#coords = coords;

    const largeBounds = [
      [-90, -180], // South-West corner (lat, lng)
      [90, 180]    // North-East corner (lat, lng)
    ];

// Create a large rectangle that covers the entire map view and beyond
    const largeRectangle = L.rectangle(largeBounds, {
      color: 'red',
      fillColor: 'red',
      fillOpacity: 0.5
    }).addTo(this.#map);


    var circle = L.circle(coords, {
      color: 'green',
      fillColor: 'green',
      fillOpacity: 0.5,
      radius: 5000,
    }).addTo(this.#map);

    // Bring the circle to the front to ensure it is displayed on top of the rectangle
    circle.bringToFront();
  }

  _renderWorkoutMarker(workout) {
    if (workout.id === "bbad631b-2f73-42ac-ae87-a3772c197a23") {
      if (this.#marker1) {
        this.#map.removeLayer(this.#marker1);
      }
      this.#marker1 = L.marker(workout.coords)
          .addTo(this.#map)
          .bindPopup(
              L.popup({
                maxWidth: 250,
                minWidth: 100,
                autoClose: false,
                closeOnClick: false,
                className: `${workout.isOnline ? "running":"cycling"}-popup`,
              })
          )
          .setPopupContent(
              `${workout.type === 'running' ? '🏃‍♂️' : '🚴‍♀️'} ${workout.description}`
          )
          .openPopup();
    }

    if (workout.id === "4f8e86a9-16a5-409e-a599-ba781723cca4") {
      if (this.#marker2) {
        this.#map.removeLayer(this.#marker2);
      }

      this.#marker2 = L.marker(workout.coords)
          .addTo(this.#map)
          .bindPopup(
              L.popup({
                maxWidth: 250,
                minWidth: 100,
                autoClose: false,
                closeOnClick: false,
                className: `${workout.isOnline ? "running" : "cycling"}-popup`,
              })
          )
          .setPopupContent(
              `${workout.type === 'running' ? '🏃‍♂️' : '🚴‍♀️'} ${workout.description}`
          )
          .openPopup();
    }

    if (workout.id === "473e551a-8e4b-4500-867e-0d6b4c8e97ff") {
      if (this.#marker3) {
        this.#map.removeLayer(this.#marker3);
      }
      this.#marker3 = L.marker(workout.coords)
          .addTo(this.#map)
          .bindPopup(
              L.popup({
                maxWidth: 250,
                minWidth: 100,
                autoClose: false,
                closeOnClick: false,
                className: `${workout.isOnline ? "running" : "cycling"}-popup`,
              })
          )
          .setPopupContent(
              `${workout.type === 'running' ? '🏃‍♂️' : '🚴‍♀️'} ${workout.description}`
          )
          .openPopup();
    }
  }

  _renderWorkout(workout) {
    // Remove the current marker if it exists

      let html = `
      <li class="workout workout--${workout.isOnline ? "running":"cycling"}" data-id="${workout.id}">
        <h2 class="workout__title">${workout.description}</h2>
        <div class="workout__details">
          <span class="workout__icon">🚴‍♀️</span>
          <span class="workout__value">${workout.distance}</span>
          <span class="workout__unit">km</span>
        </div>
        <div class="workout__details">
          <span class="workout__icon">⏱</span>
          <span class="workout__value">${workout.duration}</span>
          <span class="workout__unit">min</span>
        </div>
    `;

      html += `
        <div class="workout__details">
          <span class="workout__icon">⚡️</span>
          <span class="workout__value">${workout.speed.toFixed(1)}</span>
          <span class="workout__unit">km/h</span>
        </div>
        <div class="workout__details">
          <span class="workout__icon">${workout.batteryLevel <= 30 ? '🪫' : '🔋'} </span>
          <span class="workout__value">${workout.batteryLevel}</span>
          <span class="workout__unit">%</span>
        </div>
      </li>
      `;

    html += `</li>`;

    // Create a DOM element from the HTML string
    const workoutElement = document.createRange().createContextualFragment(html)
        .querySelector('li');

    // Update or remove existing workout element
    const existingWorkoutElement = document.querySelector(`.workout[data-id="${workout.id}"]`);

    if (existingWorkoutElement) {
      // Replace existing element with updated one
      existingWorkoutElement.replaceWith(workoutElement);
    } else {
      // Insert new element
      containerWorkouts.insertAdjacentElement('beforeend', workoutElement);
    }

    // Update internal references to DOM elements
    if (workout.id === "bbad631b-2f73-42ac-ae87-a3772c197a23") {
      this.#workout1 = workoutElement;
    } else if (workout.id === "4f8e86a9-16a5-409e-a599-ba781723cca4") {
      this.#workout2 = workoutElement;
    } else if (workout.id === "473e551a-8e4b-4500-867e-0d6b4c8e97ff") {
      this.#workout3 = workoutElement;
    }
  }

  _moveToPopup(e) {
    // BUGFIX: When we click on a workout before the map has loaded, we get an error. But there is an easy fix:
    if (!this.#map) return;

    const workoutEl = e.target.closest('.workout');

    if (!workoutEl) return;

    const workout = this.workouts.find(
        work => work.id === workoutEl.dataset.id
    );

    this.#map.setView(workout.coords, this.#mapZoomLevel, {
      animate: true,
      pan: {
        duration: 1,
      },
    });

    // using the public interface
    // workout.click();
  }

  _setLocalStorage() {
    localStorage.setItem('workouts', JSON.stringify(this.workouts));
  }

  _getLocalStorage() {
    const data = JSON.parse(localStorage.getItem('workouts'));

    if (!data) return;

    this.workouts = data;

    this.workouts.forEach(work => {
      this._renderWorkout(work);
    });
  }

  reset() {
    localStorage.removeItem('workouts');
    location.reload();
  }
}

const app = new App();

function getRandomNumber(min, max) {
  // Generate a random decimal number between 0 and 1
  const randomDecimal = Math.random();

  // Scale the random decimal to the range between min and max
  const randomNumber = randomDecimal * (max - min) + min;

  // Return the random number (you might want to round it to an integer)
  return randomNumber;
}

let dist1 = 0;
let dist2 = 0;
let dist3 = 0;
let coord1 = [];
let coord2 = [];
let coord3 = [];
let speed1 = 0;
let speed2 = 0;
let speed3 = 0;
let duration1 = 0;
let duration2 = 0;
let duration3 = 0;

function calculateDistance(lat1, lon1, lat2, lon2) {
  const R = 6371; // Radius of the Earth in km
  const dLat = deg2rad(lat2 - lat1);
  const dLon = deg2rad(lon2 - lon1);

  const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos(deg2rad(lat1)) * Math.cos(deg2rad(lat2)) *
      Math.sin(dLon / 2) * Math.sin(dLon / 2);

  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

  const distance = R * c; // Distance in km

  return distance;
}

function deg2rad(deg) {
  return deg * (Math.PI / 180);
}

function fetchData() {
  fetch('http://localhost:3000/arduino-data')
      .then(response => {
        if (!response.ok) {
          throw new Error('Network response was not ok');
        }
        return response.json();
      })
      .then(datas => {
        // Handle the data received from the backend
        console.log(datas);

        app.workouts = [];

        datas.forEach(data => {
          const id = data[0];
          const properties = data[1];
          let lat, lng;
          let coords =[];
          let duration;
          let dist = 0;
          let isOnline;
          let batteryLevel;

          properties.forEach(property => {
            if (property.name === "Gps") {
              lat = property.last_value.lat;
              lng = property.last_value.lon;
              coords = [lat, lng];
              if (id === "bbad631b-2f73-42ac-ae87-a3772c197a23") {
                if (coord1.length > 0) {
                  dist = calculateDistance(coord1[0], coord1[1], coords[0], coords[1]);
                }
                coord1 = coords;
                duration = duration1 + 1;
                duration1 += 1;
                speed1 = (speed1 + dist)/2;
                dist1 += dist;
                dist = dist1;
              }

              if (id === "4f8e86a9-16a5-409e-a599-ba781723cca4") {
                if (coord2.length > 0) {
                  dist = calculateDistance(coord2[0], coord2[1], coords[0], coords[1]);
                }
                coord2 = coords;
                duration = duration2 + 1;
                duration2 += 1;
                speed2 = (speed2 + dist)/2;
                dist2 += dist;
                dist = dist2;
              }

              if (id === "473e551a-8e4b-4500-867e-0d6b4c8e97ff") {
                if (coord3.length > 0) {
                  dist = calculateDistance(coord3[0], coord3[1], coords[0], coords[1]);
                }
                coord3 = coords;
                duration = duration3 + 1;
                duration3 += 1;
                speed3 = (speed3 + dist)/2;
                dist3 += dist;
                dist = dist3;
              }
              const valueUpdatedAt = property.value_updated_at;

              // Parse the timestamp string into a Date object
              const updatedTime = new Date(valueUpdatedAt);

              // Calculate the time difference in milliseconds
              const currentTime = new Date();
              const timeDifference = currentTime - updatedTime;

              // Threshold to consider the device online (30 seconds)
              const onlineThreshold = 30 * 1000; // 30 seconds in milliseconds

              // Check if the device is online based on the time difference
              isOnline = timeDifference <= onlineThreshold;

              console.log(`Device ${id} is online: ${isOnline}, time difference : ${timeDifference}, value updated at : ${valueUpdatedAt}, 
              distance : ${dist}`);

            }

            if (property.name === "Battery") {
              batteryLevel = property.last_value;
            }

          })
          const apiTest = new Cycling(coords, dist.toFixed(3), (duration/60).toFixed(2), batteryLevel, id, isOnline);
          app.workouts.push(apiTest);
          app._renderWorkout(apiTest);
          app._renderWorkoutMarker(apiTest);
        });
        app._setLocalStorage();
      })
      .catch(error => {
        // Handle any errors that occurred during the fetch
        console.error('Fetch error:', error);
      });

  // Schedule the next request
  setTimeout(fetchData, 1000);
}

// Start the periodic data fetching
fetchData();

// have to delete previous markers, previous cache, previous workouts