import { Component, OnInit } from '@angular/core';
import { DocumentsService } from '../../services/documents.service';
import { AuthService } from '../../services/auth.service';
import { IonicModule, PopoverController } from '@ionic/angular';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-notifications',
  templateUrl: './notifications.component.html',
  styleUrls: ['./notifications.component.css'],
  standalone: true,
  imports: [IonicModule, CommonModule]
})
export class NotificationsComponent implements OnInit {
  notifications: any[] = [];

  constructor(
    private documentsService: DocumentsService,
    private authService: AuthService,
    private popoverController: PopoverController
  ) {}

  ngOnInit() {
    this.loadNotifications();
  }

  loadNotifications() {
    this.documentsService.getNotifications().subscribe({
      next: (data) => {
        this.notifications = data;
      },
      error: (err) => console.error(err)
    });
  }

  markAsRead(notifId: string) {
    this.documentsService.markNotificationRead(notifId).subscribe({
      next: () => {
        this.loadNotifications(); // Rafraîchir la liste
      },
      error: (err) => console.error(err)
    });
  }

  closePopover() {
    this.popoverController.dismiss();
  }
}