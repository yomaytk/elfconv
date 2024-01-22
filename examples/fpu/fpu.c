#include <stdio.h>

#define ROWS 5
#define COLS 3

// Function to calculate the average of an array
double calculateAverage(double arr[], int length) {
  double sum = 0.0;
  for (int i = 0; i < length; i++) {
    sum += arr[i];
  }
  return sum / length;
}

// Function to find the index of the maximum value in an array
int findMaxIndex(double arr[], int length) {
  int maxIndex = 0;
  double maxValue = arr[0];

  for (int i = 1; i < length; i++) {
    if (arr[i] > maxValue) {
      maxValue = arr[i];
      maxIndex = i;
    }
  }

  return maxIndex;
}

int main() {
  // 2D array of doubles
  double data[ROWS][COLS] = {
      {3.1, 4.2, 5.3}, {2.0, 4.5, 6.1}, {8.5, 4.3, 2.1}, {1.2, 3.4, 5.6}, {7.8, 9.0, 1.2}};

  double averages[ROWS];

  // Calculate the average of each row
  for (int i = 0; i < ROWS; i++) {
    averages[i] = calculateAverage(data[i], COLS);
    printf("Average of row %d: %f\n", i, averages[i]);
  }

  // Find the row with the maximum average
  int maxRowIndex = findMaxIndex(averages, ROWS);
  printf("Row %d has the maximum average: %f\n", maxRowIndex, averages[maxRowIndex]);

  return 0;
}
