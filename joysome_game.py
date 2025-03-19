import pygame
import math

# Initialize Pygame
pygame.init()

# Screen dimensions
WIDTH, HEIGHT = 800, 600
screen = pygame.display.set_mode((WIDTH, HEIGHT))
pygame.display.set_caption("Multiverse Adventure: Smooth Movable Hero")

# Colors
WHITE = (255, 255, 255)
BLACK = (0, 0, 0)
LIGHT_BLUE = (173, 216, 230)

# Player properties
player_pos = [WIDTH // 2, HEIGHT // 2]
player_size = 50
player_sides = 4  # Default: Square
player_color = LIGHT_BLUE
player_angle = 0  # Start with 0 degrees for simplicity
player_velocity = [0, 0]  # [horizontal, vertical]
gravity = 0.2  # Gravity
jump_speed = -10  # Jump speed
move_speed = 3  # Movement speed
on_ground = True
landing_frames = 0  # Counter for landing animation
target_angle = 0  # Target angle for landing alignment

# Floor properties
floor_height = 500
floor_color = BLACK

# Function to draw a regular polygon
def draw_polygon(surface, color, sides, position, size, angle):
    points = []
    for i in range(sides):
        # Calculate each vertex of the polygon
        theta = (360 / sides) * i + angle
        x = position[0] + size * math.cos(math.radians(theta))
        y = position[1] + size * math.sin(math.radians(theta))
        points.append((x, y))
    pygame.draw.polygon(surface, color, points)

# Function to calculate the bounding box height
def calculate_bounding_box_height(size, sides, angle):
    # Calculate the maximum Y extent of the polygon
    max_y = -float('inf')
    for i in range(sides):
        theta = (360 / sides) * i + angle
        y = size * math.sin(math.radians(theta))
        if y > max_y:
            max_y = y
    return max_y

# Function to align the polygon to the floor
def align_to_floor(sides, angle):
    # Calculate the angle needed to align a side parallel to the ground
    angle_per_side = 360 / sides
    # Find the nearest multiple of angle_per_side
    aligned_angle = round(angle / angle_per_side) * angle_per_side
    # Adjust for the initial offset (e.g., 45 degrees for a square)
    if sides == 4:  # Square
        return aligned_angle + 45
    elif sides == 3:  # Triangle
        return aligned_angle + 30
    elif sides == 5:  # Pentagon
        return aligned_angle + 36
    else:
        return aligned_angle

# Main loop
def main():
    global player_pos, player_angle, player_velocity, on_ground, landing_frames, target_angle

    running = True
    while running:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running = False
            elif event.type == pygame.KEYDOWN:
                if event.key == pygame.K_SPACE and on_ground:  # Jump
                    player_velocity[1] = jump_speed
                    on_ground = False
                    landing_frames = 0  # Reset landing animation

        # Handle continuous key presses
        keys = pygame.key.get_pressed()
        if keys[pygame.K_LEFT]:
            player_velocity[0] = -move_speed
        elif keys[pygame.K_RIGHT]:
            player_velocity[0] = move_speed
        else:
            player_velocity[0] = 0

        # Update player position
        player_pos[0] += player_velocity[0]
        player_pos[1] += player_velocity[1]

        # Apply gravity
        if not on_ground:
            player_velocity[1] += gravity

        # Check for landing
        bounding_box_height = calculate_bounding_box_height(player_size, player_sides, player_angle)
        if player_pos[1] + bounding_box_height >= floor_height:
            player_pos[1] = floor_height - bounding_box_height  # Adjust height based on bounding box
            player_velocity[1] = 0
            on_ground = True
            # Set target angle for landing alignment
            target_angle = align_to_floor(player_sides, player_angle)
            landing_frames = 10  # Start landing animation

        # Rotate the polygon while jumping
        if not on_ground:
            player_angle += 5  # Rotation speed

        # Smoothly align the polygon to the floor during landing
        if landing_frames > 0:
            player_angle = pygame.math.lerp(player_angle, target_angle, 0.2)  # Smooth interpolation
            landing_frames -= 1

        # Draw the screen
        screen.fill(WHITE)
        # Draw the floor
        pygame.draw.rect(screen, floor_color, (0, floor_height, WIDTH, HEIGHT - floor_height))
        # Draw the player
        draw_polygon(screen, player_color, player_sides, player_pos, player_size, player_angle)
        pygame.display.flip()

    pygame.quit()

if __name__ == "__main__":
    main()